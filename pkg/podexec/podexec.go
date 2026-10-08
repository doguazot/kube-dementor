package podexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	osexec "os/exec"
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

const (
	ViaExec  = "pods/exec"
	ViaRexec = "kubectl-rexec"
)

type ExitError struct {
	Code int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("command exited with code %d inside the container", e.Code)
}

type Result struct {
	Output string

	Err error

	Via string
}

var fixedPluginPaths = []string{
	"/usr/local/bin/kubectl-rexec",
}

func FindPlugin() string {
	if p, err := osexec.LookPath("kubectl-rexec"); err == nil {
		return p
	}
	for _, p := range fixedPluginPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func Run(ctx context.Context, sess *kubectx.Session, ns, pod, container, cmd string) Result {
	out, apiErr := apiExec(ctx, sess, ns, pod, container, cmd)
	if apiErr == nil {
		return Result{Output: out, Via: ViaExec}
	}

	if ctx.Err() != nil {
		return Result{Output: out, Err: apiErr, Via: ViaExec}
	}
	plugin := FindPlugin()
	if plugin == "" {
		return Result{Output: out, Err: apiErr, Via: ViaExec}
	}
	rOut, rErr := rexecExec(ctx, sess, ns, pod, container, cmd, plugin)
	var exitErr *ExitError
	if rErr == nil || errors.As(rErr, &exitErr) {
		return Result{Output: rOut, Err: rErr, Via: ViaRexec}
	}

	return Result{
		Output: rOut,
		Err:    fmt.Errorf("pods/exec: %v; kubectl-rexec: %w", apiErr, rErr),
		Via:    ViaRexec,
	}
}

func apiExec(ctx context.Context, sess *kubectx.Session, ns, pod, container, cmd string) (string, error) {
	if sess == nil || sess.Client == nil {
		return "", errors.New("no session client")
	}
	req := sess.Client.CoreV1().RESTClient().Post().
		Resource("pods").Namespace(ns).Name(pod).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   []string{"sh", "-c", cmd},
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(sess.RestCfg, http.MethodPost, req.URL())
	if err != nil {
		return "", err
	}
	var stdout, stderr strings.Builder
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: io.Writer(&stdout),
		Stderr: io.Writer(&stderr),
	})
	return stdout.String() + stderr.String(), err
}

func rexecExec(ctx context.Context, sess *kubectx.Session, ns, pod, container, cmd, plugin string) (string, error) {
	args := []string{"exec", pod, "-n", ns}
	if container != "" {
		args = append(args, "-c", container)
	}
	if sess != nil && sess.Info.Name != "" {
		args = append(args, "--context", sess.Info.Name)
	}
	args = append(args, "--", "sh", "-c", cmd)

	c := osexec.CommandContext(ctx, plugin, args...)
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	err := c.Run()
	combined := stdout.String() + stderr.String()
	var exitErr *osexec.ExitError
	if errors.As(err, &exitErr) {
		return combined, &ExitError{Code: exitErr.ExitCode()}
	}
	return combined, err
}
