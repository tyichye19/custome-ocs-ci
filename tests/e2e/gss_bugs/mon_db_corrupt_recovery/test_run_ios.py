import logging
import pytest

from ocs_ci.ocs.bucket_utils import s3_put_object, s3_get_object, verify_s3_object_integrity, sync_object_directory, retrieve_test_objects_to_pod, get_objects
from ocs_ci.ocs import constants
from ocs_ci.ocs.ocp import switch_to_default_rook_cluster_project
from ocs_ci.ocs.resources.objectbucket import OBC
from ocs_ci.ocs.resources.pod import get_pod_obj

logger = logging.getLogger(__name__)

class TestIOs():

    def test_ios(self,project_factory, multi_dc_pod,mcg_obj, bucket_factory, awscli_pod, rgw_bucket_factory):
        project = project_factory()

        rwo_rbd_pods = multi_dc_pod(
            num_of_pvcs=1,
            pvc_size=5,
            project=project,
            access_mode="RWO",
            pool_type="rbd",
        )
        rwo_cephfs_pods = multi_dc_pod(
            num_of_pvcs=1,
            pvc_size=5,
            project=project,
            access_mode="RWO",
            pool_type="cephfs",
        )
        curl_cmd = (
            f""" curl {constants.REMOTE_FILE_URL} --output /tmp/ceph.tar.gz """
        )
        from ocs_ci.utility.utils import run_cmd

        pods = rwo_rbd_pods + rwo_cephfs_pods
        run_cmd(cmd=curl_cmd)
        import ocs_ci.ocs.resources.pod as pod_helpers

        for po in pods:
            pod_helpers.upload(
                po.name,
                constants.FILE_PATH,
                "/mnt/",
                namespace=project.namespace,
            )

        logger.info('running obc ios')

        bucket_name = bucket_factory(amount=1, interface="OC")[0].name
        obc1 = ObcIOs(mcg_obj,bucket_name)
        obc1.obc_ios()

        logger.info('Running RGW IOs')
        rgw_io(awscli_pod, rgw_bucket_factory)
        switch_to_default_rook_cluster_project()
        #get_old_rgw_objects()





class ObcIOs:
    """
    Class for running OBC IOs with retries ,
    needed in the case of disruptive ops like nooba core pod delete
    """

    def __init__(self, mcg_obj, bucket_name):
        """
        Initializer function
        mcg_obj (obj): An MCG object containing the MCG S3 connection credentials
        bucket_name (str): Name of the bucket to run IOs
        """
        self.bucket_name = bucket_name
        self.mcg_obj = mcg_obj
        logger.info(f"bucket name is {self.bucket_name}")

    def obc_ios(self):
        """
        Creates bucket then writes, reads and deletes objects
        """
        obj_data = "A string data"
        from uuid import uuid4

        logger.info(f"working on bucket name {self.bucket_name}")
        for _ in range(0, 50):
            key = "Object-key-" + f"{uuid4().hex}"
            logger.info(
                f"Write, read and delete object with key: {key} {self.bucket_name}"
            )
            assert s3_put_object(
                self.mcg_obj, self.bucket_name, key, obj_data
            ), f"Failed: Put object, {key}"

            assert s3_get_object(
                self.mcg_obj, self.bucket_name, key
            ), f"Failed: Get object, {key}"

def rgw_io(awscli_pod, rgw_bucket_factory):
    """
    Test object integrity using md5sum
    """
    from ocs_ci.ocs.resources.objectbucket import OBC
    bucketname = rgw_bucket_factory(1, "rgw-oc")[0].name
    obc_obj = OBC(bucketname)
    original_dir = "/original"
    result_dir = "/result"
    awscli_pod.exec_cmd_on_pod(command=f"mkdir {result_dir}")
    # Retrieve a list of all objects on the test-objects bucket and
    # downloads them to the pod
    full_object_path = f"s3://{bucketname}"

    downloaded_files = retrieve_test_objects_to_pod(awscli_pod, original_dir)
    # # Write all downloaded objects to the new bucket
    sync_object_directory(awscli_pod, original_dir, full_object_path, obc_obj)

    logger.info(awscli_pod.name)
    logger.info("Downloading all objects from RGW bucket to awscli pod")

    sync_object_directory(awscli_pod, full_object_path, result_dir, obc_obj)
    logger.info('verifying md5sum, after mondb recovery')
    for obj in downloaded_files:
        assert verify_s3_object_integrity(
            original_object_path=f"{original_dir}/{obj}",
            result_object_path=f"{result_dir}/{obj}",
            awscli_pod=awscli_pod,
        ), "Checksum comparision between original and result object failed"

    """
    use this bucket name and  awscli pod name in get_old_rgw_objects()
    """
    logger.info(f'bucket name is {bucketname}')
    logger.info(f' aws cli pod name is {awscli_pod.name}')

def get_old_rgw_objects():
    """
    Function to check if old rgw bucket and objects are present and intact
        """
    # get awscli pod name from oc get po
    awscli_pod = get_pod_obj('function-awscli-relay-pod-414758eec3f246', namespace='openshift-storage')
    # capture rgw bucket name before
    bucketname = 'rgw-oc-bucket-8ad3ae9ee02d49758eb5c26d3f'
    obc_obj = OBC(bucketname)
    original_dir = "/original"
    result_dir = "/result"
    full_object_path = f"s3://{bucketname}"
    get_objects(awscli_pod, full_object_path, obc_obj)
    logger.info("Downloading all objects from RGW bucket to awscli pod")
    downloaded_files = retrieve_test_objects_to_pod(awscli_pod, original_dir)

    sync_object_directory(awscli_pod, full_object_path, result_dir, obc_obj)
    logger.info('verifying md5sum, after mondb recovery')
    for obj in downloaded_files:
        assert verify_s3_object_integrity(
            original_object_path=f"{original_dir}/{obj}",
            result_object_path=f"{result_dir}/{obj}",
            awscli_pod=awscli_pod,
        ), "Checksum comparision between original and result object failed"


