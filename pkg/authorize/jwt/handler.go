package jwt

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/openshift/telemeter/pkg/authorize"
	"github.com/openshift/telemeter/pkg/store/ratelimited"
	"golang.org/x/time/rate"
)

type authorizeClusterHandler struct {
	partitionKey    string
	labels          map[string]string
	expireInSeconds int64
	signer          *Signer
	clusterAuth     authorize.ClusterAuthorizer
	limit           time.Duration
	limits          map[string]*rate.Limiter
}

// NewAuthorizerHandler creates an authorizer HTTP endpoint that will authorize the cluster
// given by the "id" form request parameter using the given cluster authorizer.
//
// Upon success, the given cluster authorizer returns a subject which is used as the client identifier
// in a generated signed JWT which is returned to the client, along with any labels.
//
// A single partition key parameter must be passed to uniquely identify the caller's data.
func NewAuthorizeClusterHandler(partitionKey string, expireInSeconds int64, limit time.Duration, signer *Signer, labels map[string]string, ca authorize.ClusterAuthorizer) *authorizeClusterHandler {
	return &authorizeClusterHandler{
		partitionKey:    partitionKey,
		expireInSeconds: expireInSeconds,
		signer:          signer,
		labels:          labels,
		clusterAuth:     ca,
		limit:           limit,
		limits:          make(map[string]*rate.Limiter),
	}
}

func (a *authorizeClusterHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(w, "Only POST is allowed to this endpoint", http.StatusMethodNotAllowed)
		return
	}

	req.Body = http.MaxBytesReader(w, req.Body, 4*1024)
	defer req.Body.Close()

	if err := req.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	uniqueIDKey := "id"
	cluster := req.Form.Get(uniqueIDKey)
	if len(cluster) == 0 {
		http.Error(w, fmt.Sprintf("The '%s' parameter must be specified via URL or url-encoded form body", uniqueIDKey), http.StatusBadRequest)
		return
	}

	limiter, ok := a.limits[cluster]
	if !ok {
		limiter = rate.NewLimiter(rate.Every(a.limit), 1)
		a.limits[cluster] = limiter
	}

	if !limiter.AllowN(time.Now(), 1) {
		http.Error(w, ratelimited.ErrWriteLimitReached.Error(), http.StatusTooManyRequests)
		return
	}

	auth := strings.SplitN(req.Header.Get("Authorization"), " ", 2)
	if strings.ToLower(auth[0]) != "bearer" {
		http.Error(w, "Only bearer authorization allowed", http.StatusUnauthorized)
		return
	}
	if len(auth) != 2 || len(strings.TrimSpace(auth[1])) == 0 {
		http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
		return
	}
	clientToken := auth[1]

	subject, err := a.clusterAuth.AuthorizeCluster(clientToken, cluster)

	if err != nil {
		type statusCodeErr interface {
			Error() string
			HTTPStatusCode() int
		}

		if scerr, ok := err.(statusCodeErr); ok {
			log.Printf("error: unable to authorize request: %v", scerr)
			if scerr.HTTPStatusCode() == http.StatusTooManyRequests {
				w.Header().Set("Retry-After", "300")
			}
			http.Error(w, scerr.Error(), scerr.HTTPStatusCode())
			return
		}

		// always hide errors from the upstream service from the client
		uid := rand.Int63()
		log.Printf("error: unable to authorize request %d: %v", uid, err)
		http.Error(w, fmt.Sprintf("Internal server error, requestid=%d", uid), http.StatusInternalServerError)
		return
	}

	labels := map[string]string{
		a.partitionKey: cluster,
	}
	for k, v := range a.labels {
		labels[k] = v
	}

	// create a token that asserts the client and the labels
	authToken, err := a.signer.GenerateToken(Claims(subject, labels, a.expireInSeconds, []string{"federate"}))
	if err != nil {
		log.Printf("error: unable to generate token: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// write the data back to the client
	data, err := json.Marshal(authorize.TokenResponse{
		Version:          1,
		Token:            authToken,
		ExpiresInSeconds: a.expireInSeconds,
		Labels:           labels,
	})

	if err != nil {
		log.Printf("error: unable to marshal token: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, err := w.Write(data); err != nil {
		log.Printf("writing auth token failed: %v", err)
	}
}
