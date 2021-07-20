import os
import threading
import time

import pytest

import girder_client_mount

DKC_API_URL = 'https://data.kitware.com/api/v1'


@pytest.fixture
def mount_client(tmp_path, request):
    gc_options = request.node.get_closest_marker('gc_options')
    gc_options = gc_options.args[0] if gc_options else {}
    gc = girder_client_mount.get_girder_client(dict(
        apiUrl=DKC_API_URL,
        sslVerify=True,
        **gc_options
    ))
    kwargs = {
        'fuse_options': 'foreground',
        'gc': gc,
    }
    mount_options = request.node.get_closest_marker('mount_options')
    mount_options = mount_options.args[0] if mount_options else {}
    kwargs.update(mount_options)
    mountThread = threading.Thread(
        target=girder_client_mount.mount_client, args=(tmp_path, ), kwargs=kwargs)
    mountThread.daemon = True
    mountThread.start()
    starttime = time.time()
    while time.time() - starttime < 30 and not os.path.exists(tmp_path / 'user'):
        time.sleep(0.05)
    yield tmp_path
    girder_client_mount.unmount_client(tmp_path)
    mountThread.join()


def test_mount(mount_client):
    root = mount_client
    assert os.path.exists(root / 'user')
    assert os.path.exists(str(root / 'user') + '/')
    assert not os.path.exists(root / 'unknown')
    assert os.path.exists(root / 'collection' / 'Girder')
    assert os.path.getsize(root / 'collection' / 'Girder') == 0
    test_path = (root / 'collection' / 'Girder' / 'Test data' / 'Core' /
                 'test_file.txt' / 'test_file.txt')
    assert os.path.exists(test_path)
    path_size = os.path.getsize(test_path)
    assert path_size > 0
    assert len(open(test_path).read()) == path_size
    with open(test_path) as fp:
        fp.seek(10)
        assert len(fp.read(20)) == 20
        fp.seek(path_size - 9)
        assert len(fp.read(20)) == 9
    with pytest.raises(Exception) as exc:
        open(test_path, 'r+')
    assert 'Read-only' in str(exc.value)


@pytest.mark.mount_options({'flatten': True})
def test_mount_flatten(mount_client):
    root = mount_client
    test_path = (root / 'collection' / 'Girder' / 'Test data' / 'Core' /
                 'test_file.txt' / 'test_file.txt')
    assert not os.path.exists(test_path)
    test_path = (root / 'collection' / 'Girder' / 'Test data' / 'Core' /
                 'test_file.txt')
    assert os.path.exists(test_path)
    path_size = os.path.getsize(test_path)
    assert path_size > 0
