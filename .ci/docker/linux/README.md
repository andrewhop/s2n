# Prerequistes
EC2 Ubuntu 18.04 host:
```
$ sudo apt-get update
$ sudo apt-get install -y awscli apt-transport-https ca-certificates curl gnupg-agent software-properties-common
$ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
$ sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
$ sudo apt-get update
$ sudo apt-get install -y docker-ce
$ sudo usermod -aG docker ${USER}
```

Build images locally with `build_images.sh`, to push to the main repository run
`push_images.sh`. To push to your own repository pass in a complete ECS url such
as `push_images.sh ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${REPOSITORY}`.

To simulate a build locally: 
```
$ docker run -it $OS:$COMPILER
$ git clone git@github.com:awslabs/aws-lc.git
$ cd aws-lc
$ ./tests/ci/run_posix_tests.sh
```