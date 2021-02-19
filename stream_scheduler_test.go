package quic

import (
	"github.com/lucas-clemente/quic-go/internal/flowcontrol"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockFlowControlManager struct{}

func isParent(n, child *node) bool {
	for _, c := range n.children {
		if c.id == child.id {
			return true
		}
	}
	return false
}

func (f *mockFlowControlManager) NewStream(streamID protocol.StreamID, contributesToConnection bool) {
	panic("not yet implemented")
}
func (f *mockFlowControlManager) RemoveStream(streamID protocol.StreamID) {
	panic("not yet implemented")
}
func (f *mockFlowControlManager) ResetStream(streamID protocol.StreamID, byteOffset protocol.ByteCount) error {
	panic("not yet implemented")
}
func (f *mockFlowControlManager) UpdateHighestReceived(streamID protocol.StreamID, byteOffset protocol.ByteCount) error {
	panic("not yet implemented")
}
func (f *mockFlowControlManager) AddBytesRead(streamID protocol.StreamID, n protocol.ByteCount) error {
	panic("not yet implemented")
}
func (f *mockFlowControlManager) GetWindowUpdates(force bool) (res []flowcontrol.WindowUpdate) {
	panic("not yet implemented")
}
func (f *mockFlowControlManager) GetReceiveWindow(streamID protocol.StreamID) (protocol.ByteCount, error) {
	panic("not yet implemented")
}
func (f *mockFlowControlManager) AddBytesSent(streamID protocol.StreamID, n protocol.ByteCount) error {
	return nil
}
func (f *mockFlowControlManager) GetBytesSent(streamID protocol.StreamID) (protocol.ByteCount, error) {
	panic("not yet implemented")
}
func (f *mockFlowControlManager) AddBytesRetrans(streamID protocol.StreamID, n protocol.ByteCount) error {
	panic("not yet implemented")
}
func (f *mockFlowControlManager) GetBytesRetrans(streamID protocol.StreamID) (protocol.ByteCount, error) {
	panic("not yet implemented")
}
func (f *mockFlowControlManager) SendWindowSize(streamID protocol.StreamID) (protocol.ByteCount, error) {
	return protocol.MaxByteCount, nil
}
func (f *mockFlowControlManager) RemainingConnectionWindowSize() protocol.ByteCount {
	return protocol.MaxByteCount
}
func (f *mockFlowControlManager) UpdateWindow(streamID protocol.StreamID, offset protocol.ByteCount) (bool, error) {
	panic("not yet implemented")
}

var _ = Describe("Stream Scheduler", func() {
	var (
		streamScheduler                    *streamScheduler
		cryptoStream, headerStream         *stream
		stream1, stream2, stream3, stream4 *stream
	)

	const (
		cryptoID = protocol.StreamID(1)
		headerID = protocol.StreamID(3)
		id1      = protocol.StreamID(4)
		id2      = protocol.StreamID(5)
		id3      = protocol.StreamID(6)
		id4      = protocol.StreamID(7)
	)

	BeforeEach(func() {
		streamScheduler = newStreamScheduler()
		cryptoStream = &stream{streamID: 1}
		headerStream = &stream{streamID: headerID}
		stream1 = &stream{streamID: id1}
		stream2 = &stream{streamID: id2}
		stream3 = &stream{streamID: id3}
		stream4 = &stream{streamID: id4}

		mockFcm := &mockFlowControlManager{}
		streamFramer := newStreamFramer(nil, mockFcm, streamScheduler)
		streamScheduler.streamFramer = streamFramer
	})

	Context("adding header stream node to dependency tree", func() {
		FIt("sets sch.root to header stream", func() {
			streamScheduler.addNode(headerStream)
			Expect(streamScheduler.root.stream).To(Equal(headerStream))
			Expect(streamScheduler.root.id).NotTo(Equal(headerStream.streamID))
		})

		FIt("sets header node active", func() {
			streamScheduler.addNode(headerStream)
			Expect(streamScheduler.root.state).To(Equal(nodeActive))
		})
	})

	Context("adding node to dependency tree", func() {
		FIt("adds node to nodeMap", func() {
			streamScheduler.addNode(stream1)
			Expect(len(streamScheduler.nodeMap)).To(Equal(1))
			streamScheduler.addNode(stream2)
			Expect(len(streamScheduler.nodeMap)).To(Equal(2))
			Expect(streamScheduler.nodeMap[id1].stream).To(Equal(stream1))
			Expect(streamScheduler.nodeMap[id2].stream).To(Equal(stream2))
			Expect(streamScheduler.nodeMap[id3]).To(BeNil())
		})

		FIt("adds sets root as its parent", func() {
			streamScheduler.addNode(stream1)
			Expect(streamScheduler.nodeMap[id1].parent).To(Equal(streamScheduler.root))
		})

		FIt("has root as parent", func() {
			streamScheduler.addNode(stream1)
			streamScheduler.setActive(id1)
			Expect(isParent(streamScheduler.root, streamScheduler.nodeMap[id1])).To(BeTrue())
		})

		FIt("is idle", func() {
			streamScheduler.addNode(stream1)
			Expect(streamScheduler.nodeMap[id1].state).To(Equal(nodeIdle))
		})

		FIt("has default weight", func() {
			streamScheduler.addNode(stream1)
			Expect(streamScheduler.nodeMap[id1].weight).To(Equal(protocol.DefaultStreamWeight))
		})

		FIt("is added to parents priority queue", func() {
			streamScheduler.addNode(stream1)
			streamScheduler.setActive(id1)
			Expect(len(streamScheduler.root.children)).To(Equal(1))
			Expect(streamScheduler.root.children[0]).To(Equal(streamScheduler.nodeMap[id1]))
		})

		FIt("does not add nil node", func() {
			err := streamScheduler.addNode(nil)
			Expect(err).To(HaveOccurred())
			Expect(len(streamScheduler.nodeMap)).To(Equal(0))
		})

		FIt("does not add crypto stream", func() {
			err := streamScheduler.addNode(cryptoStream)
			Expect(err).ToNot(HaveOccurred())
			n, ok := streamScheduler.nodeMap[cryptoID]
			Expect(n).To(BeNil())
			Expect(ok).To(Equal(false))
			Expect(len(streamScheduler.nodeMap)).To(Equal(0))
		})
	})

	Context("setting weight", func() {
		FIt("sets a new weight on existing nodes", func() {
			streamScheduler.addNode(stream1)
			err := streamScheduler.maybeSetWeight(id1, 255)
			Expect(err).ToNot(HaveOccurred())
			Expect(streamScheduler.nodeMap[id1].weight).To(Equal(uint8(255)))
			err = streamScheduler.maybeSetWeight(id2, 255)
			Expect(err).To(HaveOccurred())
		})

		FIt("does not set weight of crypto stream", func() {
			Expect(streamScheduler.maybeSetWeight(cryptoID, 255)).To(BeNil())
		})

		FIt("does not set weight of header stream", func() {
			streamScheduler.addNode(headerStream)
			Expect(streamScheduler.maybeSetWeight(headerID, 255)).To(BeNil())
			Expect(streamScheduler.root.weight).To(Equal(protocol.DefaultStreamWeight))
		})

		FIt("sets the childrens weight of the parent", func() {
			streamScheduler.addNode(headerStream)
			streamScheduler.addNode(stream1)
			streamScheduler.addNode(stream2)
			streamScheduler.setActive(id1)
			streamScheduler.setActive(id2)

			w1 := uint8(3)
			w2 := uint8(9)

			streamScheduler.maybeSetWeight(id1, w1)
			streamScheduler.maybeSetWeight(id2, w2)

			// childrensWeight adds 1 to the weight of each child
			Expect(streamScheduler.root.childrensWeight).To(Equal(uint32(w1 + w2 + 2)))
		})
	})

	Context("setting non-exclusive parent", func() {
		FIt("sets parent to a sibling", func() {
			//
			//		                    root
			//		root                  |
			//      /  \       -->        1
			//     1    2                 |
			//                            2
			//
			streamScheduler.addNode(headerStream)
			streamScheduler.addNode(stream1)
			streamScheduler.addNode(stream2)
			streamScheduler.setActive(id1)
			streamScheduler.setActive(id2)

			n1 := streamScheduler.nodeMap[id1]
			n2 := streamScheduler.nodeMap[id2]

			Expect(n1.parent).To(Equal(streamScheduler.root))
			Expect(n2.parent).To(Equal(streamScheduler.root))
			Expect(isParent(streamScheduler.root, n1)).To(BeTrue())
			Expect(isParent(streamScheduler.root, n2)).To(BeTrue())
			Expect(isParent(n1, n2)).To(BeFalse())
			Expect(len(streamScheduler.root.children)).To(Equal(2))

			err := streamScheduler.maybeSetParent(id2, id1, false)
			Expect(err).NotTo(HaveOccurred())
			Expect(n2.parent).To(Equal(n1))
			Expect(isParent(n1, n2)).To(BeTrue())
			Expect(n1.parent).To(Equal(streamScheduler.root))
			Expect(isParent(streamScheduler.root, n1)).To(BeTrue())
			Expect(isParent(streamScheduler.root, n2)).To(BeFalse())

			Expect(len(streamScheduler.root.children)).To(Equal(1))
			Expect(streamScheduler.root.children[0]).To(Equal(n1))
			Expect(len(n1.children)).To(Equal(1))
			Expect(n1.children[0]).To(Equal(n2))
		})

		FIt("sets parent to a previous descendant", func() {
			//
			//		                    root 0
			//		root                  |
			//       |          -->       3  6
			//       1                    |
			//       |                    1  4
			//       2                    |
			//      / \                   2  5
			//     3   4                  |
			//                            4  7
			//
			// Set up dependencies
			streamScheduler.addNode(headerStream)
			streamScheduler.addNode(stream1)
			streamScheduler.addNode(stream2)
			streamScheduler.addNode(stream3)
			streamScheduler.addNode(stream4)
			streamScheduler.setActive(id3)
			streamScheduler.setActive(id4)

			n1 := streamScheduler.nodeMap[id1]
			n2 := streamScheduler.nodeMap[id2]
			n3 := streamScheduler.nodeMap[id3]
			//n4 := streamScheduler.nodeMap[id4]

			err := streamScheduler.maybeSetParent(id2, id1, false)
			Expect(err).NotTo(HaveOccurred())
			err = streamScheduler.maybeSetParent(id3, id2, false)
			Expect(err).NotTo(HaveOccurred())
			err = streamScheduler.maybeSetParent(id4, id2, false)
			Expect(err).NotTo(HaveOccurred())

			// Set new parent of n1 to n3
			err = streamScheduler.maybeSetParent(id1, id3, false)
			Expect(err).NotTo(HaveOccurred())

			// Check if n3 has been updated correctly
			Expect(n3.parent).To(Equal(streamScheduler.root))
			Expect(n1.parent).To(Equal(n3))
			Expect(len(n3.children)).To(Equal(1))

			// Check if root has been updated correctly
			Expect(isParent(streamScheduler.root, n3)).To(BeTrue())
			Expect(isParent(streamScheduler.root, n1)).To(BeFalse())
			Expect(len(streamScheduler.root.children)).To(Equal(1))

			// Check if (remaining) child of n1 remains unchanged
			Expect(n2.parent).To(Equal(n1))
			Expect(isParent(n1, n2)).To(BeTrue())
			Expect(len(n1.children)).To(Equal(1))
		})

		// TODO: does not set self as parent
		FIt("does not set illegal parents", func() {
			streamScheduler.addNode(cryptoStream)
			streamScheduler.addNode(headerStream)
			streamScheduler.addNode(stream1)
			n1 := streamScheduler.nodeMap[id1]

			// Setting self as parent
			err := streamScheduler.maybeSetParent(id1, id1, false)
			Expect(err).To(HaveOccurred())
			Expect(n1.parent).To(Equal(streamScheduler.root))

			// Setting crypto stream as parent
			err = streamScheduler.maybeSetParent(id1, cryptoID, false)
			Expect(err).To(HaveOccurred())
			Expect(n1.parent).To(Equal(streamScheduler.root))

			// Setting unknown stream as parent
			err = streamScheduler.maybeSetParent(id1, id2, false)
			Expect(err).To(HaveOccurred())
			Expect(n1.parent).To(Equal(streamScheduler.root))

			// Setting parent of unknown stream
			err = streamScheduler.maybeSetParent(id2, id1, false)
			Expect(err).To(HaveOccurred())
			Expect(n1.parent).To(Equal(streamScheduler.root))

			// Setting parent of crypto stream
			err = streamScheduler.maybeSetParent(cryptoID, id1, false)
			Expect(err).To(HaveOccurred())

			// Setting parent of header stream
			err = streamScheduler.maybeSetParent(headerID, id1, false)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("setting exclusivity", func() {

		FIt("sets exclusivity (same parent)", func() {
			//
			//		                    root
			//	   root                   |
			//       |         -->        1
			//       1                    |
			//      / \                   2
			//     2   3                  |
			//                            3
			//
			streamScheduler.addNode(headerStream)
			streamScheduler.addNode(stream1)
			streamScheduler.addNode(stream2)
			streamScheduler.setActive(id2)
			streamScheduler.addNode(stream3)
			streamScheduler.setActive(id3)
			n1 := streamScheduler.nodeMap[id1]
			n2 := streamScheduler.nodeMap[id2]
			n3 := streamScheduler.nodeMap[id3]
			err := streamScheduler.maybeSetParent(id2, id1, false)
			Expect(err).NotTo(HaveOccurred())
			err = streamScheduler.maybeSetParent(id3, id1, false)
			Expect(err).NotTo(HaveOccurred())

			err = streamScheduler.maybeSetParent(id2, id1, true)
			Expect(err).NotTo(HaveOccurred())

			Expect(n1.parent).To(Equal(streamScheduler.root))
			Expect(isParent(streamScheduler.root, n1)).To(BeTrue())
			Expect(len(streamScheduler.root.children)).To(Equal(1))

			Expect(n2.parent).To(Equal(n1))
			Expect(isParent(n1, n2)).To(BeTrue())
			Expect(len(n1.children)).To(Equal(1))

			Expect(n3.parent).To(Equal(n2))
			Expect(isParent(n2, n3)).To(BeTrue())
			Expect(len(n2.children)).To(Equal(1))
		})

		FIt("sets parent to a sibling (without children)", func() {
			//
			//		                    root
			//		root                  |
			//      /  \         -->      2
			//     1    2                 |
			//                            1
			//
			streamScheduler.addNode(headerStream)
			streamScheduler.addNode(stream1)
			streamScheduler.setActive(id1)
			streamScheduler.addNode(stream2)
			streamScheduler.setActive(id2)
			n1 := streamScheduler.nodeMap[id1]
			n2 := streamScheduler.nodeMap[id2]

			err := streamScheduler.maybeSetParent(id1, id2, true)
			Expect(err).NotTo(HaveOccurred())
			Expect(n1.parent).To(Equal(n2))
			Expect(isParent(n2, n1)).To(BeTrue())
			Expect(isParent(streamScheduler.root, n2)).To(BeTrue())
			Expect(len(streamScheduler.root.children)).To(Equal(1))
			Expect(len(n2.children)).To(Equal(1))
		})

		FIt("sets parent to a sibling (with children)", func() {
			//
			//		root                root
			//		/  \                  |
			//     1    2        -->      2
			//         / \                |
			//        3   4               1
			//                           / \
			//                          3   4
			//
			streamScheduler.addNode(headerStream)
			streamScheduler.addNode(stream1)
			streamScheduler.setActive(id1)
			streamScheduler.addNode(stream2)
			streamScheduler.addNode(stream3)
			streamScheduler.setActive(id3)
			streamScheduler.addNode(stream4)
			streamScheduler.setActive(id4)
			n1 := streamScheduler.nodeMap[id1]
			n2 := streamScheduler.nodeMap[id2]
			n3 := streamScheduler.nodeMap[id3]
			n4 := streamScheduler.nodeMap[id4]
			err := streamScheduler.maybeSetParent(id3, id2, false)
			Expect(err).NotTo(HaveOccurred())
			err = streamScheduler.maybeSetParent(id4, id2, false)
			Expect(err).NotTo(HaveOccurred())

			// Set n1 as exclusive child to n2
			err = streamScheduler.maybeSetParent(id1, id2, true)
			Expect(err).NotTo(HaveOccurred())

			// n2 should now be parent of n1
			Expect(n1.parent).To(Equal(n2))
			Expect(isParent(n2, n1)).To(BeTrue())
			Expect(len(n2.children)).To(Equal(1))

			// parent of n2 should not be changed
			Expect(n2.parent).To(Equal(streamScheduler.root))
			Expect(isParent(streamScheduler.root, n2)).To(BeTrue())
			Expect(len(streamScheduler.root.children)).To(Equal(1))

			// n1 should adopt n3 and n4 from n2
			Expect(n3.parent).To(Equal(n1))
			Expect(n4.parent).To(Equal(n1))
			Expect(isParent(n1, n3)).To(BeTrue())
			Expect(isParent(n1, n4)).To(BeTrue())
			Expect(len(n1.children)).To(Equal(2))
		})

		FIt("sets parent to a previous descendant", func() {
			//
			//		root                root
			//		  |                   |
			//        1        -->        2
			//        |                   |
			//        2                   1
			//       / \                 / \
			//      3   4               3   4
			//
			streamScheduler.addNode(headerStream)
			streamScheduler.addNode(stream1)
			streamScheduler.addNode(stream2)
			streamScheduler.addNode(stream3)
			streamScheduler.addNode(stream4)
			streamScheduler.setActive(id3)
			streamScheduler.setActive(id4)

			n1 := streamScheduler.nodeMap[id1]
			n2 := streamScheduler.nodeMap[id2]
			n3 := streamScheduler.nodeMap[id3]
			n4 := streamScheduler.nodeMap[id4]
			err := streamScheduler.maybeSetParent(id2, id1, false)
			Expect(err).NotTo(HaveOccurred())
			err = streamScheduler.maybeSetParent(id3, id2, false)
			Expect(err).NotTo(HaveOccurred())
			err = streamScheduler.maybeSetParent(id4, id2, false)
			Expect(err).NotTo(HaveOccurred())

			// Set n1 as exclusive child to n2
			err = streamScheduler.maybeSetParent(id1, id2, true)
			Expect(err).NotTo(HaveOccurred())

			// n2 should now be parent of n1
			Expect(n1.parent).To(Equal(n2))
			Expect(isParent(n2, n1)).To(BeTrue())
			Expect(len(n2.children)).To(Equal(1))

			// parent of n2 now be the root
			Expect(n2.parent).To(Equal(streamScheduler.root))
			Expect(isParent(streamScheduler.root, n2)).To(BeTrue())
			Expect(len(streamScheduler.root.children)).To(Equal(1))

			// n1 should adopt n3 and n4 from n2
			Expect(n3.parent).To(Equal(n1))
			Expect(n4.parent).To(Equal(n1))
			Expect(isParent(n1, n3)).To(BeTrue())
			Expect(isParent(n1, n4)).To(BeTrue())
			Expect(len(n1.children)).To(Equal(2))
		})
	})

	Context("setting active", func() {
		FIt("sets node active", func() {
			streamScheduler.addNode(stream1)
			streamScheduler.setActive(id1)
			Expect(streamScheduler.nodeMap[id1].state).To(Equal(nodeActive))
		})

		FIt("adds idle parents to the tree", func() {
			streamScheduler.addNode(headerStream)
			streamScheduler.addNode(stream1)
			streamScheduler.addNode(stream2)

			n1 := streamScheduler.nodeMap[id1]

			err := streamScheduler.maybeSetParent(id2, id1, false)
			Expect(err).NotTo(HaveOccurred())

			Expect(len(streamScheduler.root.children)).To(Equal(0))
			Expect(streamScheduler.root.activeChildren).To(Equal(uint16(0)))
			Expect(len(n1.children)).To(Equal(0))
			Expect(n1.activeChildren).To(Equal(uint16(0)))

			streamScheduler.setActive(id2)

			Expect(len(streamScheduler.root.children)).To(Equal(1))
			Expect(streamScheduler.root.activeChildren).To(Equal(uint16(1)))
			Expect(len(n1.children)).To(Equal(1))
			Expect(n1.activeChildren).To(Equal(uint16(1)))
		})

		FIt("does not add active parents to the tree", func() {
			streamScheduler.addNode(headerStream)
			streamScheduler.addNode(stream1)
			streamScheduler.addNode(stream2)
			streamScheduler.addNode(stream3)

			n1 := streamScheduler.nodeMap[id1]

			err := streamScheduler.maybeSetParent(id2, id1, false)
			Expect(err).NotTo(HaveOccurred())
			err = streamScheduler.maybeSetParent(id3, id1, false)
			Expect(err).NotTo(HaveOccurred())

			streamScheduler.setActive(id2)

			Expect(len(streamScheduler.root.children)).To(Equal(1))
			Expect(streamScheduler.root.activeChildren).To(Equal(uint16(1)))
			Expect(len(n1.children)).To(Equal(1))
			Expect(n1.activeChildren).To(Equal(uint16(1)))

			streamScheduler.setActive(id3)

			Expect(len(streamScheduler.root.children)).To(Equal(1))
			Expect(streamScheduler.root.activeChildren).To(Equal(uint16(1)))
			Expect(len(n1.children)).To(Equal(2))
			Expect(n1.activeChildren).To(Equal(uint16(2)))
		})

		FIt("does not set unknown stream active", func() {
			err := streamScheduler.setActive(id1)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("scheduling", func() {

		FIt("returns nil if there is no data to send", func() {
			streamScheduler.addNode(stream1)
			streamScheduler.addNode(stream2)
			streamScheduler.addNode(stream3)
			streamScheduler.addNode(stream4)

			err := streamScheduler.maybeSetParent(id3, id1, false)
			Expect(err).ToNot(HaveOccurred())
			err = streamScheduler.maybeSetParent(id4, id1, false)
			Expect(err).ToNot(HaveOccurred())

			s := streamScheduler.schedule()
			Expect(s).To(BeNil())
		})

		FIt("schedules stream frame", func() {
			streamScheduler.addNode(stream1)
			streamScheduler.addNode(stream2)
			streamScheduler.addNode(stream3)
			streamScheduler.addNode(stream4)

			err := streamScheduler.maybeSetParent(id3, id1, false)
			Expect(err).ToNot(HaveOccurred())
			err = streamScheduler.maybeSetParent(id4, id1, false)
			Expect(err).ToNot(HaveOccurred())

			streamScheduler.setActive(id1)

			stream1.dataForWriting = []byte("foobar")
			s := streamScheduler.schedule()
			Expect(s.id).To(Equal(stream1.streamID))
		})
	})
})
