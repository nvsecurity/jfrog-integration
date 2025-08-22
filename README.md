# NightVision / JFrog DAST Scan Evidence Collection 

NightVision offers DAST and API discovery capabilities that complement JFrog's artifact management and software distribution solutions. By integrating NightVision into the JFrog platform, JFrog can help developers not only manage and deliver trusted binaries, but also validate the security of the live web apps and APIs that those artifacts power. 

This document describes how to use the NightVision CLI and the JFrog CLI to build and upload Docker images, run DAST scan against local containers, and attach the evidence to Docker images deployed to JFrog Artifactory. 

Refer to [nightvision-evidence.yml](https://github.com/nvsecurity/jfrog-integration/blob/main/.github/workflows/nightvision-evidence.yml) for the complete script.

## Prerequisites

* Install JFrog CLI ([instructions](https://jfrog.com/getcli/)).
* Create a JFrog Docker repository ([instructions](https://jfrog.com/help/r/jfrog-artifactory-documentation/set-up-a-docker-repository)).
* Generate the Docker repository access token (Go to `Artifactory->Artifacts` and select the repository created in the previous step. Click the `Set Me Up` button. Go to the `Configure` tab in the `Set Up A Docker Client` popup and click the `Generate Token` button to generate the access token).
* Create the key pair for evidence collection and upload the public key to JFrog ([instructions](https://jfrog.com/help/r/jfrog-artifactory-documentation/evidence-setup)).
* Install NightVision CLI ([instructions](https://docs.nightvision.net/docs/installing-the-cli)).
* Create a NightVision authentication token ([instructions](https://docs.nightvision.net/docs/api-tokens)).
* Create the NightVision scan target ([instructions](https://docs.nightvision.net/docs/targets-copy)) and (optionally) authentication script ([instructions](https://docs.nightvision.net/docs/authentication)).
* Configure the following repository variables in GitHub
  * `ARTIFACTORY_URL` (url of the JFrog artifactory server)
  * `BUILD_NAME` (name of the Docker image build)
  * `DOCKER_REPO` (name of the JFrog Docker repository)
  * `IMAGE_NAME` (name of the Docker image)
  * `NIGHTVISION_PROVIDER_ID` (name of the provider that created the evidence)
  * `NIGHTVISION_SCAN_RESULT_PREDICATE_TYPE` (predicate type for the DAST scan result)
  * `NIGHTVISION_OPENAPI_SPEC_PREDICATE_TYPE` (predicate type for the OpenAPI spec)
* Configure the following repository secrets in GitHub 
  * `ARTIFACTORY_ACCESS_TOKEN` (access token for the JFrog artifactory server)
  * `JF_USER` (user name of the JFrog artifactory server)
  * `PRIVATE_KEY` (private key used for signing the evidence file) 
  * `NIGHTVISION_TOKEN` (access token for the NightVision platform)

## Preparation

### Install JFrog CLI

Install the latest version of the JFrog CLI and performs checkout. Please note a valid access token is required. 

```yaml
- name: Install jfrog cli
  uses: jfrog/setup-jfrog-cli@v4
  env:
    JF_URL: ${{ vars.ARTIFACTORY_URL }}
    JF_ACCESS_TOKEN: ${{ secrets.ARTIFACTORY_ACCESS_TOKEN }}

- uses: actions/checkout@v4
```

### Log Into the Artifactory Docker Registry

Log into the Docker registry, and sets up QEMU and Docker Buildx in preparation for building the Docker image

```yaml
- name: Log in to Artifactory Docker Registry
  uses: Docker/login-action@v3
  with:
    registry: ${{ vars.ARTIFACTORY_URL }}
    username: ${{ secrets.JF_USER }}
    password: ${{ secrets.ARTIFACTORY_ACCESS_TOKEN }}

- name: Set up QEMU
  uses: Docker/setup-qemu-action@v3    

- name: Set up Docker Buildx
  uses: Docker/setup-buildx-action@v3
  with:
    platforms: linux/amd64,linux/arm64
    install: true
```

### Install NightVision CLI

```yaml
- name: Install NightVision cli
  run: | 
    wget -c https://downloads.nightvision.net/binaries/latest/nightvision_latest_linux_amd64.tar.gz -O - | tar -xz; sudo mv nightvision /usr/local/bin/
```

## Build the Docker Image 

Build the Docker image and upload it to artifactory

```yaml
- name: Build Docker image
  run: |
    URL=$(echo ${{ vars.ARTIFACTORY_URL }} | sed 's|^https://||')
    REPO_URL=${URL}'/javaspringvulny-local'
    Docker build --build-arg REPO_URL=${REPO_URL} -f dockerfile . \
    --tag ${REPO_URL}/javaspringvulny:${{ github.run_number }} \
    --output=type=image --platform linux/amd64 --metadata-file=build-metadata --push
    jf rt build-docker-create javaspringvulny-local --image-file build-metadata --build-name ${{ vars.BUILD_NAME }} --build-number ${{ github.run_number }}
```

## Run the NightVision API Discovery and DAST Scan

### Generate API Swagger file

Scan the API source code automatically generate the Swagger file 

```yaml
- name: Extract API documentation from code
  run: |
    nightvision swagger extract . --target ${NIGHTVISION_TARGET} --lang java || true
      if [ ! -e ${NIGHTVISION_OPENAPI_SPEC} ]; then
        cp backup-openapi-spec.json ${NIGHTVISION_OPENAPI_SPEC}
      fi
```

### Start the application

```yaml
- name: Start the app
  run: docker compose up -d; sleep 10
```

### Run DAST Scan

Scan the application using the auto-generated Swagger file

```yaml 
- name: Scan the app
  run: |
    nightvision scan ${NIGHTVISION_TARGET} --auth ${NIGHTVISION_AUTH} > scan-results.txt
    nightvision export sarif -s "$(head -n 1 scan-results.txt)" --swagger-file ${NIGHTVISION_OPENAPI_SPEC} -o ${NIGHTVISION_SCAN_RESULT}
```

### Markdown Conversion

Convert the scan result from Sarif to Markdown

```yaml
- name: Convert sarif to markdown
  run: |
    python sarif_to_markdown.py ${NIGHTVISION_SCAN_RESULT} ${NIGHTVISION_SCAN_RESULT_MARKDOWN}
```

## Attach DAST Scan Evidence 

Sign the DAST scan result using the private key and upload it to the Docker repository

```yaml
- name: Upload evidence to the Docker package
  run: |
    jf evd create \
    --package-name ${{ vars.IMAGE_NAME }} \
    --package-version ${{ github.run_number }} \
    --package-repo-name ${{ vars.DOCKER_REPO }} \
    --key ${{ secrets.PRIVATE_KEY }} \
    --key-alias nightvision_evidence_key \
    --provider-id ${{ vars.NIGHTVISION_PROVIDER_ID }} \
    --predicate ${{ env.NIGHTVISION_SCAN_RESULT }} \
    --predicate-type ${{ vars.NIGHTVISION_SCAN_RESULT_PREDICATE_TYPE }} \
    --markdown ${{ env.NIGHTVISION_SCAN_RESULT_MARKDOWN }}
```

## Attach OpenAPI Spec Evidence 

Sign the auto-generated OpenAPI spec using the private key and upload it to the Docker repository

```yaml
- name: Upload OpenAPI spec to the Docker package
  run: |
    jf evd create \
    --package-name ${{ vars.IMAGE_NAME }} \
    --package-version "${{ env.IMAGE_TAG }}" \
    --package-repo-name ${{ vars.DOCKER_REPO }} \
    --key "${{ secrets.PRIVATE_KEY }}" \
    --key-alias nightvision_evidence_key \
    --provider-id ${{ vars.NIGHTVISION_PROVIDER_ID }} \
    --predicate ${{ env.NIGHTVISION_OPENAPI_SPEC }} \
    --predicate-type ${{ vars.NIGHTVISION_OPENAPI_SPEC_PREDICATE_TYPE }}
```

## Note 

1. It appears the `jf rt build-docker-create` command will create two different package versions: a version using the GitHub run number and a version using the `sha256` digest. The evidence will be attached to the version using the GitHub run number.

