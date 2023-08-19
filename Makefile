

hub:
	docker build -f cmd/hub/Dockerfile -t hub.comcast.net/k8s-eng/artifacthub/hub:v1.14.0-rdei .
	docker push hub.comcast.net/k8s-eng/artifacthub/hub:v1.14.0-rdei
