FROM kalilinux/kali-rolling
# Install packages and set locale
RUN apt-get update \
    && apt-get install -y locales nano ssh sudo unzip python3 curl libkf5config-bin  wget \
    && localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8 \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH tunnel using ngrok
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=en_US.utf8


WORKDIR /root
ENV LANG en_US.UTF-8 
ENV LC_ALL C.UTF-8

# Install ssh, wget, and unzip

# Download and unzip ngrok
RUN wget -O ngrok.zip https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3.5-stable-linux-amd64.zip > /dev/null 2>&1
RUN unzip ngrok.zip

# Create shell script
RUN echo "./ngrok config add-authtoken ${NGROK_TOKEN} &&" >>/kali.sh
RUN echo "./ngrok tcp 22 &>/dev/null &" >>/kali.sh


# Create directory for SSH daemon's runtime files
RUN echo '/usr/sbin/sshd -D' >>/kali.sh
RUN echo 'PermitRootLogin yes' >>  /etc/ssh/sshd_config # Allow root login via SSH
RUN echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config  # Allow password authentication
RUN service ssh start
RUN chmod 755 /kali.sh

# Expose port

# Start the shell script on container startup

COPY /root /
# add local files
# ports and volumes

CMD  /kali.sh
ENTRYPOINT ["/bin/bash", "/COPY /root /
