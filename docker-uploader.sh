# It need to be separated from builder.sh because we download the assets from Github's release packages,
# so firt we need to release and then release the docker image.
echo "Uploading docker image to Dockerhub..."
if ! systemctl is-active docker.service >/dev/null; then
  echo "Please start docker.service."
  exit
fi

if cd docker && docker build --pull -f Dockerfile -t edu4rdshl/findomain:latest . > /dev/null \
  && docker push edu4rdshl/findomain:latest > /dev/null; then
  echo "Image uploaded sucessfully."
else
  echo "An error has ocurred while uploading the docker image."
  exit
fi
