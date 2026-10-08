package ingestor

import (
	"context"
	"fmt"
	"log"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type RawClusterData struct {
	Pods                []corev1.Pod
	Nodes               []corev1.Node
	ServiceAccounts     []corev1.ServiceAccount
	Roles               []rbacv1.Role
	ClusterRoles        []rbacv1.ClusterRole
	RoleBindings        []rbacv1.RoleBinding
	ClusterRoleBindings []rbacv1.ClusterRoleBinding
}

type Ingestor struct {
	client    kubernetes.Interface
	pageSize  int64
	namespace string
}

func New(client kubernetes.Interface, pageSize int64, namespace string) *Ingestor {
	if pageSize <= 0 {
		pageSize = 500
	}
	return &Ingestor{client: client, pageSize: pageSize, namespace: namespace}
}

func (i *Ingestor) Collect(ctx context.Context) (*RawClusterData, error) {
	if i.namespace != "" {
		log.Printf("[ingestor] Starting resource collection (namespace: %s)...", i.namespace)
	} else {
		log.Println("[ingestor] Starting resource collection (cluster-wide)...")
	}

	data := &RawClusterData{}
	var err error

	data.Pods, err = i.listPods(ctx)
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	log.Printf("[ingestor] Collected %d pods", len(data.Pods))

	data.Nodes, err = i.listNodes(ctx)
	if err != nil {
		if i.namespace != "" {
			log.Printf("[ingestor] Skipping nodes (no cluster-scope permission): %v", err)
		} else {
			return nil, fmt.Errorf("list nodes: %w", err)
		}
	} else {
		log.Printf("[ingestor] Collected %d nodes", len(data.Nodes))
	}

	data.ServiceAccounts, err = i.listServiceAccounts(ctx)
	if err != nil {
		if i.namespace != "" {
			log.Printf("[ingestor] Skipping service accounts: %v", err)
		} else {
			return nil, fmt.Errorf("list service accounts: %w", err)
		}
	} else {
		log.Printf("[ingestor] Collected %d service accounts", len(data.ServiceAccounts))
	}

	data.Roles, err = i.listRoles(ctx)
	if err != nil {
		if i.namespace != "" {
			log.Printf("[ingestor] Skipping roles: %v", err)
		} else {
			return nil, fmt.Errorf("list roles: %w", err)
		}
	} else {
		log.Printf("[ingestor] Collected %d roles", len(data.Roles))
	}

	data.ClusterRoles, err = i.listClusterRoles(ctx)
	if err != nil {
		if i.namespace != "" {
			log.Printf("[ingestor] Skipping cluster roles (no cluster-scope permission): %v", err)
		} else {
			return nil, fmt.Errorf("list cluster roles: %w", err)
		}
	} else {
		log.Printf("[ingestor] Collected %d cluster roles", len(data.ClusterRoles))
	}

	data.RoleBindings, err = i.listRoleBindings(ctx)
	if err != nil {
		if i.namespace != "" {
			log.Printf("[ingestor] Skipping role bindings: %v", err)
		} else {
			return nil, fmt.Errorf("list role bindings: %w", err)
		}
	} else {
		log.Printf("[ingestor] Collected %d role bindings", len(data.RoleBindings))
	}

	data.ClusterRoleBindings, err = i.listClusterRoleBindings(ctx)
	if err != nil {
		if i.namespace != "" {
			log.Printf("[ingestor] Skipping cluster role bindings (no cluster-scope permission): %v", err)
		} else {
			return nil, fmt.Errorf("list cluster role bindings: %w", err)
		}
	} else {
		log.Printf("[ingestor] Collected %d cluster role bindings", len(data.ClusterRoleBindings))
	}

	log.Println("[ingestor] Resource collection complete.")
	return data, nil
}

func (i *Ingestor) listPods(ctx context.Context) ([]corev1.Pod, error) {
	var all []corev1.Pod
	continueToken := ""
	for {
		list, err := i.client.CoreV1().Pods(i.namespace).List(ctx, metav1.ListOptions{
			Limit:    i.pageSize,
			Continue: continueToken,
		})
		if err != nil {
			return nil, err
		}
		all = append(all, list.Items...)
		if list.Continue == "" {
			break
		}
		continueToken = list.Continue
	}
	return all, nil
}

func (i *Ingestor) listNodes(ctx context.Context) ([]corev1.Node, error) {
	var all []corev1.Node
	continueToken := ""
	for {
		list, err := i.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{
			Limit:    i.pageSize,
			Continue: continueToken,
		})
		if err != nil {
			return nil, err
		}
		all = append(all, list.Items...)
		if list.Continue == "" {
			break
		}
		continueToken = list.Continue
	}
	return all, nil
}

func (i *Ingestor) listServiceAccounts(ctx context.Context) ([]corev1.ServiceAccount, error) {
	var all []corev1.ServiceAccount
	continueToken := ""
	for {
		list, err := i.client.CoreV1().ServiceAccounts(i.namespace).List(ctx, metav1.ListOptions{
			Limit:    i.pageSize,
			Continue: continueToken,
		})
		if err != nil {
			return nil, err
		}
		all = append(all, list.Items...)
		if list.Continue == "" {
			break
		}
		continueToken = list.Continue
	}
	return all, nil
}

func (i *Ingestor) listRoles(ctx context.Context) ([]rbacv1.Role, error) {
	var all []rbacv1.Role
	continueToken := ""
	for {
		list, err := i.client.RbacV1().Roles(i.namespace).List(ctx, metav1.ListOptions{
			Limit:    i.pageSize,
			Continue: continueToken,
		})
		if err != nil {
			return nil, err
		}
		all = append(all, list.Items...)
		if list.Continue == "" {
			break
		}
		continueToken = list.Continue
	}
	return all, nil
}

func (i *Ingestor) listClusterRoles(ctx context.Context) ([]rbacv1.ClusterRole, error) {
	var all []rbacv1.ClusterRole
	continueToken := ""
	for {
		list, err := i.client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{
			Limit:    i.pageSize,
			Continue: continueToken,
		})
		if err != nil {
			return nil, err
		}
		all = append(all, list.Items...)
		if list.Continue == "" {
			break
		}
		continueToken = list.Continue
	}
	return all, nil
}

func (i *Ingestor) listRoleBindings(ctx context.Context) ([]rbacv1.RoleBinding, error) {
	var all []rbacv1.RoleBinding
	continueToken := ""
	for {
		list, err := i.client.RbacV1().RoleBindings(i.namespace).List(ctx, metav1.ListOptions{
			Limit:    i.pageSize,
			Continue: continueToken,
		})
		if err != nil {
			return nil, err
		}
		all = append(all, list.Items...)
		if list.Continue == "" {
			break
		}
		continueToken = list.Continue
	}
	return all, nil
}

func (i *Ingestor) listClusterRoleBindings(ctx context.Context) ([]rbacv1.ClusterRoleBinding, error) {
	var all []rbacv1.ClusterRoleBinding
	continueToken := ""
	for {
		list, err := i.client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{
			Limit:    i.pageSize,
			Continue: continueToken,
		})
		if err != nil {
			return nil, err
		}
		all = append(all, list.Items...)
		if list.Continue == "" {
			break
		}
		continueToken = list.Continue
	}
	return all, nil
}
