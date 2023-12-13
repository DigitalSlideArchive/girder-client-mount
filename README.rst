===================
Girder Client Mount
===================

Mount a Girder server as a local FUSE mount.

Installation
------------

You must have Python >= 3.8 and libfuse installed.

Use pip ::

    pip install girder-client-mount


Example Usage
-------------

Create a mount directory (e.g., ``mkdir /mnt/remote_girder``), then mount it via ::

    girder-client-mount /mnt/remote_girder --username= --password= --apiurl=https://data.kitware.com/api/v1

You can optionally use diskcache to persist data locally.  Add appropriate options (see help for more details) ::

    girder-client-mount /mnt/remote_girder --username= --password= --apiurl=https://data.kitware.com/api/v1 --options diskcache

On Windows, specify an available drive letter for the mount.  You probably will need to also set an environment variable to point to a libfuse compatible dll. ::

    set FUSE_LIBRARY_PATH=c:\Program Files\Dokan\DokanLibrary-1.5.0\dokanfuse1.dll
    girder-client-mount A --username= --password= --apiurl=https://data.kitware.com/api/v1
