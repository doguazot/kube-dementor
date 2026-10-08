package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"

	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

type Config struct {
	Kubeconfig string

	Neo4jURI      string
	Neo4jUser     string
	Neo4jPassword string
	Neo4jDatabase string

	PageSize int64

	Namespace string
}

func DefaultConfig() *Config {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		if home := homedir.HomeDir(); home != "" {
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
	}

	cfg := &Config{
		Kubeconfig:    kubeconfig,
		Neo4jURI:      getEnvOrDefault("NEO4J_URI", "bolt://localhost:7687"),
		Neo4jUser:     getEnvOrDefault("NEO4J_USER", "neo4j"),
		Neo4jPassword: getEnvOrDefault("NEO4J_PASS", "password"),
		Neo4jDatabase: getEnvOrDefault("NEO4J_DATABASE", "neo4j"),
		PageSize:      500,
		Namespace:     os.Getenv("KUBE_DEMENTOR_NAMESPACE"),
	}
	return cfg
}

func NewKubeClient(cfg *Config) (*kubernetes.Clientset, error) {
	session, err := NewKubeSession(cfg)
	if err != nil {
		return nil, err
	}
	return session.Client, nil
}

func NewKubeSession(cfg *Config) (*kubectx.Session, error) {

	restCfg, err := rest.InClusterConfig()
	if err != nil {

		restCfg, err = clientcmd.BuildConfigFromFlags("", cfg.Kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to build k8s config: %w", err)
		}
	}
	restCfg.Timeout = 30 * time.Second
	restCfg.QPS, restCfg.Burst = 50, 100

	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s clientset: %w", err)
	}
	info := kubectx.ContextInfo{ClusterServer: restCfg.Host, Namespace: cfg.Namespace}
	if cfg.Kubeconfig != "" {
		if raw, err := clientcmd.LoadFromFile(cfg.Kubeconfig); err == nil {
			info.Name = raw.CurrentContext
			if current := raw.Contexts[raw.CurrentContext]; current != nil {
				info.ClusterName, info.UserName = current.Cluster, current.AuthInfo
				if info.Namespace == "" {
					info.Namespace = current.Namespace
				}
			}
		}
	}
	return &kubectx.Session{Info: info, RestCfg: restCfg, Client: clientset, Discovery: clientset.Discovery()}, nil
}

func getEnvOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
