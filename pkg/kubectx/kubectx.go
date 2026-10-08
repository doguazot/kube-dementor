package kubectx

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/util/homedir"
)

type ContextInfo struct {
	Name           string
	ClusterName    string
	ClusterServer  string
	UserName       string
	Namespace      string
	KubeconfigPath string

	ServerVersion string
	Platform      string
}

type Session struct {
	Info      ContextInfo
	RestCfg   *rest.Config
	Client    *kubernetes.Clientset
	Discovery discovery.DiscoveryInterface
}

func Resolve(ctxName, kubeconfigPath string) (*Session, error) {

	if kubeconfigPath == "" {
		kubeconfigPath = os.Getenv("KUBECONFIG")
	}
	if kubeconfigPath == "" {
		if home := homedir.HomeDir(); home != "" {
			kubeconfigPath = filepath.Join(home, ".kube", "config")
		}
	}

	var apiCfg *clientcmdapi.Config
	var err error
	if kubeconfigPath != "" {
		apiCfg, err = clientcmd.LoadFromFile(kubeconfigPath)
		if err != nil {
			return nil, fmt.Errorf("load kubeconfig %q: %w", kubeconfigPath, err)
		}
	}

	if apiCfg == nil {
		restCfg, err := rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("no kubeconfig and not in-cluster: %w", err)
		}
		clientset, err := kubernetes.NewForConfig(restCfg)
		if err != nil {
			return nil, fmt.Errorf("build in-cluster client: %w", err)
		}
		info := ContextInfo{
			Name:          "in-cluster",
			ClusterName:   "in-cluster",
			ClusterServer: restCfg.Host,
		}
		populateVersion(clientset, &info)
		return &Session{Info: info, RestCfg: restCfg, Client: clientset, Discovery: clientset.Discovery()}, nil
	}

	if ctxName == "" {
		ctxName = apiCfg.CurrentContext
	}
	if ctxName == "" {
		return nil, fmt.Errorf("no context specified and kubeconfig has no current-context (kubeconfig=%s)", kubeconfigPath)
	}

	ctxObj, ok := apiCfg.Contexts[ctxName]
	if !ok {
		names := make([]string, 0, len(apiCfg.Contexts))
		for n := range apiCfg.Contexts {
			names = append(names, n)
		}
		return nil, fmt.Errorf("context %q not found in kubeconfig %s (available: %s)",
			ctxName, kubeconfigPath, strings.Join(names, ", "))
	}

	configOverrides := &clientcmd.ConfigOverrides{CurrentContext: ctxName}
	clientCfg := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath},
		configOverrides,
	)
	restCfg, err := clientCfg.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("build rest config for context %q: %w", ctxName, err)
	}
	restCfg.Timeout = 30 * time.Second
	restCfg.QPS = 50
	restCfg.Burst = 100

	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("build kubernetes client: %w", err)
	}

	info := ContextInfo{
		Name:           ctxName,
		ClusterName:    ctxObj.Cluster,
		UserName:       ctxObj.AuthInfo,
		Namespace:      ctxObj.Namespace,
		KubeconfigPath: kubeconfigPath,
	}
	if clu, ok := apiCfg.Clusters[ctxObj.Cluster]; ok {
		info.ClusterServer = clu.Server
	}

	if err := probe(clientset); err != nil {
		return nil, fmt.Errorf("cannot reach cluster %q (%s): %w", info.ClusterName, info.ClusterServer, err)
	}
	populateVersion(clientset, &info)

	return &Session{
		Info:      info,
		RestCfg:   restCfg,
		Client:    clientset,
		Discovery: clientset.Discovery(),
	}, nil
}

func ListContexts(kubeconfigPath string) ([]string, string, error) {
	if kubeconfigPath == "" {
		kubeconfigPath = os.Getenv("KUBECONFIG")
	}
	if kubeconfigPath == "" {
		if home := homedir.HomeDir(); home != "" {
			kubeconfigPath = filepath.Join(home, ".kube", "config")
		}
	}
	apiCfg, err := clientcmd.LoadFromFile(kubeconfigPath)
	if err != nil {
		return nil, "", err
	}
	names := make([]string, 0, len(apiCfg.Contexts))
	for n := range apiCfg.Contexts {
		names = append(names, n)
	}
	return names, apiCfg.CurrentContext, nil
}

func probe(cs *kubernetes.Clientset) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := cs.Discovery().ServerVersion()
	_ = ctx
	return err
}

func populateVersion(cs *kubernetes.Clientset, info *ContextInfo) {
	v, err := cs.Discovery().ServerVersion()
	if err != nil {
		return
	}
	info.ServerVersion = v.GitVersion
	info.Platform = v.Platform
}
