# Openrelik Mach-O and ELF Worker

This repository contains the code for an [OpenRelik](https://openrelik.org/) Worker that provides workflow tasks to parse [Mach-O](https://en.wikipedia.org/wiki/Mach-O) and [ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) files.

You can add the Worker to your OpenRelik [Getting started](https://openrelik.org/docs/getting-started/) setup by adding the following section to the [```docker-compose.yml```](https://github.com/openrelik/openrelik-deploy/blob/main/docker/docker-compose.yml) file.

```console
  openrelik-worker-parser:
      container_name: openrelik-worker-parser
      image: europe-west1-docker.pkg.dev/repos-daschwanden/labs/openrelik-worker-parser:v0.1
      restart: always
      environment:
        - REDIS_URL=redis://openrelik-redis:6379
      volumes:
        - ./data:/usr/share/openrelik/data
      command: "celery --app=src.app worker --task-events --concurrency=4 --loglevel=INFO -Q openrelik-worker-parser"
```
