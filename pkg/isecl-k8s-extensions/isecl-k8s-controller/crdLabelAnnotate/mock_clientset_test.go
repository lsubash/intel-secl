package crdLabelAnnotate

import (
	"context"
	"log"

	apiv1 "k8s.io/api/core/v1"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

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
