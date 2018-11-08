## Running in Docker
There are a few environment variables for this cli.

`KEYPATH` (optional) the path where the keyfiles will be stored. DEFAULT is /.ssh

`PUBKEY_FILENAME` (optional) the filename of the public RSA file. DEFAULT is id_rsa.pub

`PRIVKEY_FILENAME` (optional) the filename of the public RSA file. DEFAULT is id_rsa

To build the CLI docker image:
```
docker build -t codechal .
```

To run the CLI with docker:
```
docker run codechal <string>
docker run --env KEYPATH=/.ssh -it keygen <string>
```

## Unit Tests
All unit tests are in util_test.go. To run, simply run `go test` in the project directory

## Continuous Integration
With more time, a continuous integration system could be put in place that does the following for each pull request:

1. run unit tests
2. run integration tests 
A suite of tests that runs the docker image with a set of known input strings, and tests the signature that it was correctly calculated by inspecting the docker image's private key file.