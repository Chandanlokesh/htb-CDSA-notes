This is a solid and detailed explanation of **containerization**, **Docker**, and related concepts. To help with revision or better clarity, here’s a **point-wise summary** that distills your notes into clear, concise takeaways. You can use this as a quick reference sheet.

---

## 📦 Containerization — Key Points

- **Definition:** Running applications in isolated environments called containers.
    
- **Purpose:** Ensures consistent behavior across different environments.
    
- **Key Technologies:** Docker, Docker Compose, LXC.
    
- **Difference from VMs:** Shares host OS kernel → lighter and faster than VMs.
    
- **Advantages:**
    
    - Lightweight and fast
        
    - Consistent environments
        
    - Scalable and portable
        
    - Suitable for microservices
        
    - Better resource usage
        
- **Analogy:** Like self-contained “stage pods” for bands at a concert.
    
- **Security:**
    
    - Containers isolate applications.
        
    - But not as isolated as VMs → prone to privilege escalation or escape if not secured properly.
        

---

## 🐳 Docker — Overview

- **Definition:** Open-source platform to build, ship, and run containers.
    
- **Concept:** Sealed, reusable "lunchbox" containing everything an app needs.
    
- **Components:**
    
    - **Docker Engine:** Core engine that runs containers.
        
    - **Dockerfile:** Script that defines how to build an image.
        
    - **Docker Hub:** Registry to find/upload container images (public & private).
        

---

## 🛠️ Docker Installation (Ubuntu)

Script installs Docker Engine and CLI tools:

```bash
# Update and install dependencies
sudo apt update -y
sudo apt install ca-certificates curl gnupg lsb-release -y

# Add Docker’s GPG key and repo
sudo mkdir -m 0755 -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt update -y
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y

# Add user to Docker group
sudo usermod -aG docker htb-student
```

Run test:

```bash
docker run hello-world
```

---

## 🏗️ Dockerfile Example — File Server with Apache & SSH

```Dockerfile
FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y apache2 openssh-server && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m docker-user && \
    echo "docker-user:password" | chpasswd

RUN chown -R docker-user:docker-user /var/www/html /var/run/apache2 /var/log/apache2 /var/lock/apache2 && \
    usermod -aG sudo docker-user && \
    echo "docker-user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

EXPOSE 22 80

CMD service ssh start && /usr/sbin/apache2ctl -D FOREGROUND
```

---

## 🔨 Build & Run Docker Image

### Build Image:

```bash
docker build -t FS_docker .
```

### Run Container (ports mapped):

```bash
docker run -p 8022:22 -p 8080:80 -d FS_docker
```

---

## ⚙️ Docker Management Commands

|Command|Description|
|---|---|
|`docker ps`|List running containers|
|`docker stop <id>`|Stop a container|
|`docker start <id>`|Start a container|
|`docker restart`|Restart a container|
|`docker rm <id>`|Remove a container|
|`docker rmi <img>`|Remove an image|
|`docker logs <id>`|View container logs|

### Notes:

- Changes inside containers are **not saved** unless a new image is built.
    
- Use **volumes** to persist data outside the container.
    
- Tools like **Docker Compose** and **Kubernetes** manage multiple containers.
    

---

## 🧱 Linux Containers (LXC)

- **Definition:** Lightweight containers using the Linux kernel.
    
- **Uses:** Control groups (cgroups) and namespaces for isolation.
    
- **Difference from VMs:** No separate OS per container → better performance.
    

---

Would you like a visual cheat sheet for Docker commands or container concepts?