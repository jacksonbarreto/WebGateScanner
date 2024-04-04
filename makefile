.PHONY: clean

clean:
	@docker run --rm -v //var/run/docker.sock:/var/run/docker.sock docker sh -c "docker images -q jacksonbarreto/webgatescanner-* | xargs -r docker rmi"
	docker system prune -f -a --volumes
up:
	docker-compose up -d

down:
	docker-compose down

get-results:
	scp -r vps:/home/jacks/results "C:\Users\jacks\Dropbox\Produção Acadêmica\Tese\system\WebGateScanner\results"
