IMAGE_NAME=persistenceone/node-operator
TAG_NAME := $(shell date '+%Y%m%d')-$(shell git rev-parse --short HEAD)
CONTAINER_NAME=pSTAKE-container
FILE=Dockerfile

DOCKER_VOLUME=\
	-v $(PWD):/usr/src/app \


# Docker commands for building and pushing docker images and containers
#
# Run `make docker-build TAG=<test-tag>` for creating testing tags
docker-build:
	docker build . -f $(FILE) -t $(IMAGE_NAME):$(TAG_NAME)

docker-run:
	docker run --rm -it --name=$(CONTAINER_NAME) \
		$(DOCKER_VOLUME) $(DOCKER_ARGS) \
		$(IMAGE_NAME):$(TAG_NAME) /bin/sh

# Handy command for running latest docker container
docker-latest-run:
	$(MAKE) docker-run TAG_NAME=latest

docker-build-push: docker-build
	docker push $(IMAGE_NAME):$(TAG_NAME)

# Handy command for tagging current tag as latest and pushing image
docker-latest-push:
	docker tag $(IMAGE_NAME):$(TAG_NAME) $(IMAGE_NAME):latest
	docker push $(IMAGE_NAME):latest

docker-clean-container:
	-docker stop $(CONTAINER_NAME)
	-docker rm $(CONTAINER_NAME)

docker-clean: docker-clean-container
	-docker rmi $(IMAGE_NAME):$(TAG_NAME)
