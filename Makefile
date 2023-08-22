# hub:v1.14.0-rdei : custom rdei changes
VERSION=v1.14.0-rdei

hub:
	docker build -f cmd/hub/Dockerfile -t hub.comcast.net/k8s-eng/artifacthub/hub:${VERSION} .
	docker push hub.comcast.net/k8s-eng/artifacthub/hub:${VERSION}


tracker:
	docker build  -f cmd/tracker/Dockerfile  -t artifacthub/tracker  -t hub.comcast.net/k8s-eng/artifacthub/tracker:${VERSION} .
	docker push hub.comcast.net/k8s-eng/artifacthub/tracker:${VERSION}


