<h1 align="center">Discover and Protect Against Remotely Exploitable Vulnerabilities with Agent Asteroid</h1>

<p align="center">
<img src="https://img.shields.io/badge/License-Apache_2.0-brightgreen.svg">
<img src="https://img.shields.io/github/languages/top/ostorlab/agent_asteroid">
<img src="https://img.shields.io/github/stars/ostorlab/agent_asteroid">
<img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg">
</p>

_The Asteroid Agent is a powerful scanner specializing in the detection of vulnerabilities that could be exploited remotely._

---

<p align="center">
<img src="https://github.com/ostorlab/agent_asteroid/blob/main/images/logo.png" alt="agent-asteroid" />
</p>

Agent Asteroid is a powerful open-source security scanner designed to detect vulnerabilities that could be exploited remotely. Developed by security team at Ostorlab, this tool provides a comprehensive solution for identifying critical security risks. At the time of writing, Agent Asteroid can detect nearly 100 critical CVEs.

## Key Features

- **Advanced Vulnerability Detection**: Agent Asteroid utilizes cutting-edge techniques to scan target systems and identify a wide range of vulnerabilities, including misconfigurations, unpatched software, and more.
- **Comprehensive CVE Coverage**: The agent can detect nearly 100 critical CVEs, helping you stay ahead of the latest security threats.
- **Seamless Integration**: The agent can be easily integrated into your existing security workflows, allowing you to incorporate vulnerability detection into your regular testing and deployment processes.
- **Extensible and Customizable**: With support for custom modules and plugins, Agent Asteroid can be tailored to meet your specific security requirements, making it a versatile tool for organizations of all sizes.
- **Open-Source Transparency**: As an open-source project, Agent Asteroid benefits from community contributions and feedback, ensuring continual improvement and the highest standards of security.

## Getting Started

To perform your first scan with Agent Asteroid, simply run the following command:

oxo scan run --install --agent agent/ostorlab/asteroid ip 8.8.8.8

This command will download and install the `agent/ostorlab/asteroid` agent and target the IP address `8.8.8.8`. For more detailed instructions and usage examples, please refer to the [OXO Documentation](https://oxo.ostorlab.co/docs).

## Contributing

We welcome contributions from the community! Whether you're interested in submitting bug reports, feature requests, or code contributions, please feel free to [open an issue](https://github.com/Ostorlab/agent_asteroid/issues/new) or [submit a pull request](https://github.com/Ostorlab/agent_asteroid/pulls). By working together, we can make Agent Asteroid an even more powerful and effective security tool.

## Join the Community

Stay up-to-date with the latest developments and connect with other security professionals by following us on [Twitter](https://twitter.com/ostorlab) and joining our [Discord server](https://discord.gg/ostorlab). We're always eager to hear your feedback and ideas!


### Build directly from the repository

 1. To build the asteroid agent you need to have [oxo](https://pypi.org/project/ostorlab/) installed in your machine. If you have already installed oxo, you can skip this step.

```shell
pip3 install ostorlab
```

 2. Clone this repository.

```shell
git clone https://github.com/Ostorlab/agent_asteroid.git && cd agent_asteroid
```

 3. Build the agent image using oxo cli.

 ```shell
 oxo agent build --file=ostorlab.yaml
 ```

 You can pass the optional flag `--organization` to specify your organisation. The organization is empty by default.

 4. Run the agent using on of the following commands:
	 * If you did not specify an organization when building the image:
    ```shell
    oxo scan run --agent agent//asteroid ip 8.8.8.8
    ```
	 * If you specified an organization when building the image:
    ```shell
    oxo scan run --agent agent/[ORGANIZATION]/asteroid ip 8.8.8.8
    ```
