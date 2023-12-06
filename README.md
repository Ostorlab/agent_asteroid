<h1 align="center">Agent Asteroid</h1>

<p align="center">
<img src="https://img.shields.io/badge/License-Apache_2.0-brightgreen.svg">
<img src="https://img.shields.io/github/languages/top/ostorlab/agent_asteroid">
<img src="https://img.shields.io/github/stars/ostorlab/agent_asteroid">
<img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg">
</p>

_The Asteroid Agent is a powerful scanner specializing in the detection of vulnerabilities that could be exploited remotely._

---
<p align="center">
<img src="https://github-production-user-asset-6210df.s3.amazonaws.com/144700714/288508129-9f949e21-d83f-46d7-846a-38cb167b540d.jpg?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20231206%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20231206T181913Z&X-Amz-Expires=300&X-Amz-Signature=68786c0102d9e0ddf23ecb45190e3731f0af61c701851174bd47a359b1bdffb6&X-Amz-SignedHeaders=host&actor_id=144700714&key_id=0&repo_id=716167641" alt="agent-asteroid" />
</p>

## Getting Started
To perform your first scan, simply run the following command:
```shell
ostorlab scan run --install --agent agent/ostorlab/asteroid ip 8.8.8.8
``` 

This command will download and install `agent/ostorlab/asteroid` and target IP `8.8.8.8`.
For more information, please refer to the [Ostorlab Documentation](https://github.com/Ostorlab/ostorlab/blob/main/README.md)


## Usage

Agent Asteroid can be installed directly from the ostorlab agent store or built from this repository.

 ### Install directly from ostorlab agent store

 ```shell
 ostorlab agent install agent/ostorlab/asteroid
 ```

You can then run the agent with the following command:
```shell
ostorlab scan run --agent agent/ostorlab/asteroid ip 8.8.8.8
```


### Build directly from the repository

 1. To build the asteroid agent you need to have [ostorlab](https://pypi.org/project/ostorlab/) installed in your machine. If you have already installed ostorlab, you can skip this step.

```shell
pip3 install ostorlab
```

 2. Clone this repository.

```shell
git clone https://github.com/Ostorlab/agent_asteroid.git && cd agent_asteroid
```

 3. Build the agent image using ostorlab cli.

 ```shell
 ostorlab agent build --file=ostorlab.yaml
 ```

 You can pass the optional flag `--organization` to specify your organisation. The organization is empty by default.

 4. Run the agent using on of the following commands:
	 * If you did not specify an organization when building the image:
    ```shell
    ostorlab scan run --agent agent//asteroid ip 8.8.8.8
    ```
	 * If you specified an organization when building the image:
    ```shell
    ostorlab scan run --agent agent/[ORGANIZATION]/asteroid ip 8.8.8.8
    ```
