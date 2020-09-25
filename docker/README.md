## Basic Usage
```
docker run -it findomain -t example.com
```

Configuration Notes:
- Pass your config to the container by bind mounting to `/opt/findomain` with the flag `-v`,   
ie. `-v $(pwd):/opt/findomain`
- Results saved with `-o` will be saved to `/opt/findomain` inside the container and consequently through the bind mount to your local host. This way the results will persist on your machine even if the container is only temporary.


## Full Example
```
docker run --rm -it -v $(pwd):/opt/findomain findomain -c config.toml -t example.com
```

---

#### Using the image from dockerhub

1. Pull the image
```
docker pull edu4rdshl/findomain
```
2. Run Findomain
```
docker run edu4rdshl/findomain
```

#### Building the image yourself
1. Clone the repo
```
git clone https://github.com/Findomain/Findomain
```

2. Build the image
```
cd Findomain/docker
docker build . -t findomain
```

3. Run it as usual
```
docker run -it findomain
```
