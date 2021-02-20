package quic

import (
	"fmt"
	"sync"

	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type streamScheduler struct {
	root         *node
	toSend       *node
	openStreams  int
	nodeMap      map[protocol.StreamID]*node
	streamFramer *streamFramer // Probably not needed anymore
	blockedLast  bool

	sync.Mutex
}

// A Priority is a stream priority in QUIC (maybe move this to internal/protocol)
type Priority struct {
	Dependency protocol.StreamID
	Weight     uint8
	Exclusive  bool
}

// A node represents a stream in the dependency tree
type node struct {
	id              protocol.StreamID // Needed, since the stream may be nil
	stream          *stream
	weight          uint8  // actual weight is weight + 1
	childrensWeight uint32 // the weight of the node's children
	state           uint8  // states: nodeIdle, nodeActive, nodeClosed
	activeChildren  uint16 // number of active children
	quantum         uint16
	parent          *node
	children        []*node
	nextChild       uint16
	lowestQuantum   uint16
	numerator       uint64
	denominator     uint64

	waiting uint8 // waiting flag for SA-ECF
}

const (
	nodeIdle uint8 = iota
	nodeActive
	nodeClosed
)

func newNode(id protocol.StreamID, stream *stream, parent *node) *node {
	return &node{
		id:            id,
		stream:        stream,
		weight:        protocol.DefaultStreamWeight,
		parent:        parent,
		state:         nodeIdle,
		lowestQuantum: 256,
		numerator:     1,
		denominator:   1,
	}
}

func newStreamScheduler() *streamScheduler {
	nodeMap := make(map[protocol.StreamID]*node)

	return &streamScheduler{
		root:    newNode(0, nil, nil),
		nodeMap: nodeMap,
	}
}

func (n *node) deactivateNode() error {
	// Try to keep node around as long as possible in order to maintain priority information
	// since the priority of a node may be altered even after its stream has finished
	// Idle branches should be kept around for at least 2 RTTs

	n.state = nodeClosed
	n.stream = nil

	if n.parent != nil && n.activeChildren == 0 {
		n.parent.removeWeight(n)
	}

	return nil
}

func (n *node) addWeight(child *node) {
	n.childrensWeight += uint32(child.weight) + 1
	n.activeChildren++
	n.children = append(n.children, child)

	if n.parent != nil && n.state != nodeActive && n.activeChildren == 1 {
		n.parent.addWeight(n)
	}
}

func (n *node) removeWeight(child *node) {
	index := 0
	for i, c := range n.children {
		if c == child {
			index = i
			break
		}
	}
	n.children = append(n.children[:index], n.children[index+1:]...)
	if len(n.children) == 0 {
		n.nextChild = 0
	} else {
		n.nextChild = n.nextChild % uint16(len(n.children))
	}

	n.childrensWeight -= uint32(child.weight) - 1
	n.activeChildren--

	if n.parent != nil && n.activeChildren == 0 {
		n.parent.removeWeight(n)
	}
}

func (n *node) skip() {
	n.quantum = 0
	if n.parent != nil {
		n.parent.nextChild = (n.parent.nextChild + 1) % uint16(len(n.parent.children))
		n.parent.skip()
	}
}

// Estimate the number of bytes which needs to be sent over the entire connection in order to complete the stream
func (sch *streamScheduler) bytesUntilCompletion(n *node) protocol.ByteCount {
	L := protocol.MaxPacketSize
	len := n.stream.lenOfDataForWriting()

	var left protocol.ByteCount
	if L < len {
		left = len - L
	} else {
		left = len
	}

	if protocol.ByteCount(n.lowestQuantum)*L >= left || sch.openStreams == 1 {
		return len
	}

	g := protocol.ByteCount(n.denominator - n.numerator)
	G := g * left
	return G + len/protocol.ByteCount(n.numerator)
}

// New nodes are intitially set to become the child of the root node
func (sch *streamScheduler) addNode(child *stream) error {
	sch.Lock()
	defer sch.Unlock()

	if child == nil {
		return fmt.Errorf("attempt to add unknown node")
	}

	if child.streamID == 1 /* Crypto stream handled separately */ {
		return nil
	}

	// Set header stream as root
	if child.streamID == 3 {
		sch.root.stream = child
		sch.root.state = nodeActive
		sch.nodeMap[3] = sch.root
		return nil
	}

	n := newNode(child.streamID, child, sch.root)
	if n.state == nodeActive {
		sch.root.addWeight(n)
	}
	sch.nodeMap[child.streamID] = n

	return nil
}

func (sch *streamScheduler) maybeSetWeight(id protocol.StreamID, weight uint8) error {
	sch.Lock()
	defer sch.Unlock()

	if id == 1 || id == 3 /* Weight does not impact crypto and header stream */ {
		return nil
	}
	n, ok := sch.nodeMap[id]
	if !ok {
		return fmt.Errorf("setting weight of unknown stream %d", id)
	}
	if n.weight == weight {
		return nil
	}

	if n.state == nodeActive || n.activeChildren > 0 {
		diff := int(weight) - int(n.weight)
		newWeight := int(n.parent.childrensWeight) + diff
		n.parent.childrensWeight = uint32(newWeight)
	}

	n.weight = weight
	return nil
}

func (sch *streamScheduler) maybeSetParent(childID, parentID protocol.StreamID, exclusive bool) error {
	sch.Lock()
	defer sch.Unlock()

	if childID == parentID {
		return fmt.Errorf("setting stream %d as its own parent", childID)
	}
	if childID == 1 {
		return fmt.Errorf("setting parent of crypto stream")
	}
	if childID == 3 {
		return fmt.Errorf("setting parent of header stream")
	}
	if parentID == 1 {
		return fmt.Errorf("setting parent to crypto stream")
	}
	if parentID == 3 {
		parentID = 0 // Is it really necessary that the root node has ID 0?
	}
	child, ok := sch.nodeMap[childID]
	if !ok {
		return fmt.Errorf("setting unknown stream %d as exclusive child of stream %d", childID, parentID)
	}
	if !exclusive && child.parent != nil && child.parent.id == parentID /* Already parent, nothing to do */ {
		return nil
	}
	newParent, ok := sch.nodeMap[parentID]
	if !ok {
		return fmt.Errorf("setting stream %d as exclusive child of unknown stream %d", childID, parentID)
	}
	oldParent := child.parent

	// RFC 7540: If a stream is made dependent on one of its own dependencies, the
	// formerly dependent stream is first moved to be dependent on the
	// reprioritized stream's previous parent.  The moved dependency retains
	// its weight.
	for n := newParent.parent; n.parent != nil; n = n.parent {
		if n == child {
			if newParent.state == nodeActive || newParent.activeChildren > 0 {
				// Only active nodes are set as children
				newParent.parent.removeWeight(newParent)
				if oldParent != nil {
					oldParent.addWeight(newParent)
				}
			}
			newParent.parent = oldParent
		}
	}

	// Remove node from its previous parent
	if child.parent != nil {
		if child.state == nodeActive || child.activeChildren > 0 {
			child.parent.removeWeight(child)
		}

		child.parent = nil
	}

	// RFC 7540: Setting a dependency with the exclusive flag for a
	// reprioritized stream causes all the dependencies of the new parent
	// stream to become dependent on the reprioritized stream.
	if exclusive {
		for _, c := range newParent.children {
			if c != newParent {
				if c.state == nodeActive || c.activeChildren > 0 {
					child.addWeight(c)
					newParent.removeWeight(c)
				}

				c.parent = child
			}
		}
	}

	child.parent = newParent
	if child.state == nodeActive || child.activeChildren > 0 {
		newParent.addWeight(child)
	}

	return nil
}

func (sch *streamScheduler) setActive(id protocol.StreamID) error {
	sch.Lock()
	defer sch.Unlock()

	if id == 1 /* Crypto stream handled separatly */ {
		return nil
	}
	if id == 3 /* Header stream is always considered active */ {
		return nil
	}

	n, ok := sch.nodeMap[id]
	if !ok {
		return fmt.Errorf("setting unknown stream %d active", id)
	}

	n.state = nodeActive
	n.parent.addWeight(n)
	sch.openStreams++

	return nil
}

// Copied from stream_framer.go
func (sch *streamScheduler) send(s *stream, maxBytes protocol.ByteCount, pth *path) (res *wire.StreamFrame, currentLen protocol.ByteCount, cont bool) {
	frame := &wire.StreamFrame{DataLenPresent: true}

	if s == nil || s.streamID == 1 /* Crypto stream is handled separately */ {
		cont = true
		return
	}

	frame.StreamID = s.streamID
	// not perfect, but thread-safe since writeOffset is only written when getting data
	frame.Offset = s.writeOffset
	frameHeaderBytes, _ := frame.MinLength(protocol.VersionWhatever) // can never error

	//if currentLen+frameHeaderBytes > maxBytes {
	if frameHeaderBytes > maxBytes {
		cont = false // theoretically, we could find another stream that fits, but this is quite unlikely, so we stop here
		return
	}
	//maxLen := maxBytes - currentLen - frameHeaderBytes
	maxLen := maxBytes - frameHeaderBytes

	var sendWindowSize protocol.ByteCount
	lenStreamData := s.lenOfDataForWriting()
	if lenStreamData != 0 {
		sendWindowSize, _ = sch.streamFramer.flowControlManager.SendWindowSize(s.streamID)
		maxLen = utils.MinByteCount(maxLen, sendWindowSize)
	}

	if maxLen == 0 {
		cont = true
		return
	}

	var data []byte
	if lenStreamData != 0 {
		// Only getDataForWriting() if we didn't have data earlier, so that we
		// don't send without FC approval (if a Write() raced).
		data = s.getDataForWriting(maxLen)
	}

	// This is unlikely, but check it nonetheless, the scheduler might have jumped in. Seems to happen in ~20% of cases in the tests.
	shouldSendFin := s.shouldSendFin()
	if data == nil && !shouldSendFin {
		cont = true
		return
	}

	if shouldSendFin {
		frame.FinBit = true
		s.sentFin()
	}

	frame.Data = data
	sch.streamFramer.flowControlManager.AddBytesSent(s.streamID, protocol.ByteCount(len(data)))
	// Finally, check if we are now FC blocked and should queue a BLOCKED frame
	if sch.streamFramer.flowControlManager.RemainingConnectionWindowSize() == 0 {
		// We are now connection-level FC blocked
		sch.streamFramer.blockedFrameQueue = append(sch.streamFramer.blockedFrameQueue, &wire.BlockedFrame{StreamID: 0})
	} else if !frame.FinBit && sendWindowSize-frame.DataLen() == 0 {
		// We are now stream-level FC blocked
		sch.streamFramer.blockedFrameQueue = append(sch.streamFramer.blockedFrameQueue, &wire.BlockedFrame{StreamID: s.StreamID()})
	}

	//res = append(res, frame)
	res = frame
	//currentLen += frameHeaderBytes + frame.DataLen()
	currentLen = frameHeaderBytes + frame.DataLen()

	if currentLen == maxBytes {
		cont = false
		return
	}

	cont = true
	return
}

func (sch *streamScheduler) traverse(n *node) (strm *node) {
	//fmt.Println("Visit", n.id)

	// Update quantum if the stream is selected in a new round
	if n.quantum == 0 {
		n.quantum = uint16(n.weight) + 1
	}

	// Gather additional info
	if n.parent != nil {
		if n.parent.activeChildren == 1 {
			n.lowestQuantum = n.parent.lowestQuantum
		} else {
			quantum := n.quantum - 1
			if quantum < n.quantum-1 {
				n.lowestQuantum = quantum
			} else {
				n.lowestQuantum = n.parent.lowestQuantum
			}
		}
		n.numerator = uint64(n.weight+1) * n.parent.numerator
		n.denominator = uint64(n.parent.childrensWeight) * n.parent.denominator
	}

	var sw protocol.ByteCount
	if n.stream != nil {
		sw, _ = sch.streamFramer.flowControlManager.SendWindowSize(n.stream.streamID)
	}

	if n.stream != nil && n.stream.finishedWriteAndSentFin() {
		sch.openStreams--
		n.deactivateNode()
		return
	}

	if n.id == 0 && n.stream != nil && n.stream.lenOfDataForWriting() > 0 && sw > 0 /* Special case for header stream, since it never closes */ {
		strm = n
	} else if n.id != 0 && n.state == nodeActive && n.quantum > 0 && n.stream != nil && !n.stream.finishedWriteAndSentFin() && sw > 0 {
		n.quantum--
		strm = n
	} else if n.activeChildren > 0 && n.quantum > 0 {
		for i := 0; i < len(n.children); i++ {
			c := n.children[n.nextChild]
			strm = sch.traverse(c)
			if strm != nil {
				n.quantum--
				break
			}
		}
	} /*else if n.parent != nil {
		n.parent.nextChild = (n.parent.nextChild + 1) % uint16(len(n.parent.children))
		return
	} */

	if (strm == nil || n.quantum == 0) && n.parent != nil && len(n.parent.children) > 0 {
		n.parent.nextChild = (n.parent.nextChild + 1) % uint16(len(n.parent.children))
	}

	return
}

func (sch *streamScheduler) schedule() *node {
	sch.Lock()
	defer sch.Unlock()

	return sch.traverse(sch.root)
}
