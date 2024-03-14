.PHONY: clean

clean:
	@docker run --rm -v //var/run/docker.sock:/var/run/docker.sock docker sh -c "docker images -q jacksonbarreto/webgatescanner-* | xargs -r docker rmi"
	docker system prune -f -a --volumes
up:
	docker-compose up -d

down:
	docker-compose down
