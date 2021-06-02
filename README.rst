===================
Girder Client Mount
===================

Mount a Girder server as a local FUSE mount.

Installation
------------

You must have Python >= 3.6 and libfuse installed.

Use pip ::

    pip install girder-client-mount

Example Usage
-------------

Create a mount directory (e.g., ``mkdir /mnt/remote_girder``), then mount it via ::

    girder-client-mount /mnt/remote_girder --username= --password= --apiurl=https://data.kitware.com/api/v1
