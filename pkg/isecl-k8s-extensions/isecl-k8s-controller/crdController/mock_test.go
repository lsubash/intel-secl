package crdController

import (
	"context"
	"log"

	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/isecl-k8s-controller/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/isecl-k8s-controller/crdLabelAnnotate"
	apiv1 "k8s.io/api/core/v1"
	corev1 "k8s.io/api/core/v1"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	k8sclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/workqueue"

	"k8s.io/client-go/kubernetes/fake"
)

type Client struct {
	Clientset kubernetes.Interface
}

func createFakeNode() (*apiv1.Node, kubernetes.Interface, error) {

	label := make(map[string]string)
	annotation := make(map[string]string)
	node := &apiv1.Node{
		TypeMeta: v1.TypeMeta{
			Kind:       "Node",
			APIVersion: "apps/v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:            "node-test",
			GenerateName:    "node-test-extension",
			SelfLink:        "",
			UID:             "0ca7b97f4e4b48c8a33566dd86d8e33d",
			ResourceVersion: "",
			Generation:      1,
			ClusterName:     "clusterTest",
			Labels:          label,
			Annotations:     annotation,
		},
		Spec: apiv1.NodeSpec{
			PodCIDR:       "",
			PodCIDRs:      []string{"1", "2", "3"},
			ProviderID:    "",
			Unschedulable: true,
			Taints: []apiv1.Taint{{
				Key:   "test-taint",
				Value: "taint-value",
			},
			},
		},
		Status: apiv1.NodeStatus{
			Capacity: apiv1.ResourceList{},
		},
	}

	typeMeta := v1.TypeMeta{
		Kind:       "Node",
		APIVersion: "apps/v1",
	}
	options := v1.CreateOptions{
		TypeMeta:     typeMeta,
		DryRun:       []string{"1", "2"},
		FieldManager: "manager",
	}

	var c Client
	c.Clientset = fake.NewSimpleClientset()
	nodePtr, err := c.Clientset.CoreV1().Nodes().Create(context.Background(), node, options)

	if err != nil {
		log.Println(err)
	}

	return nodePtr, c.Clientset, err
}

func createMockQueue() workqueue.RateLimitingInterface {
	queue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), constants.WgName)
	queue.Add("test-1")

	return queue
}

//Mocking ApiHelpers
type MockK8sHelpers struct{}

//Getk8sClientHelper returns helper object and clientset to fetch node
func NewMockGetk8sClientHelper() (crdLabelAnnotate.APIHelpers, k8sclient.Clientset) {
	helper := crdLabelAnnotate.APIHelpers(MockK8sHelpers{})
	defaultLog.Infof("Getk8sClientHelper %v", helper)

	return helper, k8sclient.Clientset{}
}

//GetNode returns node API based on nodename
func (h MockK8sHelpers) GetNode(cli *k8sclient.Clientset, NodeName string) (*corev1.Node, error) {
	label := make(map[string]string)
	annotation := make(map[string]string)

	label["sgxEnable"] = "false"

	return &corev1.Node{
		TypeMeta: v1.TypeMeta{
			Kind:       "Node",
			APIVersion: "apps/v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:            "node-test",
			GenerateName:    "node-test-extension",
			SelfLink:        "",
			UID:             "0ca7b97f4e4b48c8a33566dd86d8e33d",
			ResourceVersion: "",
			Generation:      1,
			ClusterName:     "clusterTest",
			Labels:          label,
			Annotations:     annotation,
		},
		Spec: apiv1.NodeSpec{
			PodCIDR:       "",
			PodCIDRs:      []string{"1", "2", "3"},
			ProviderID:    "",
			Unschedulable: true,
			Taints: []apiv1.Taint{{
				Key:   "test-taint",
				Value: "taint-value",
			},
			},
		},
		Status: apiv1.NodeStatus{
			Capacity: apiv1.ResourceList{},
		},
	}, nil
}

func (h MockK8sHelpers) UpdateNode(cli *k8sclient.Clientset, n *corev1.Node) error {
	return nil
}

func (h MockK8sHelpers) DeleteNode(cli *k8sclient.Clientset, nodeName string) error {
	return nil
}
