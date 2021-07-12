import logging
import time

from ocs_ci.framework.pytest_customization.marks import tier1
from ocs_ci.framework.testlib import skipif_ocs_version, skipif_ocp_version
from ocs_ci.ocs.ui.block_pool import BlockPoolUI
from ocs_ci.helpers.helpers import create_unique_resource_name


logger = logging.getLogger(__name__)

class TestPvcUserInterface(object):
    """
    Test PVC User Interface

    """

    replica = 2
    compression = True

    @tier1
    @skipif_ocs_version("<4.6")
    def test_create_delete_pool(self, setup_ui ):
        """
        test create delete pool
        """
        block_pool_ui_object = BlockPoolUI(setup_ui)
        pool_name = create_unique_resource_name("test", "rbd-pool")
        block_pool_ui_object.create_pool(pool_name, self.replica, self.compression)
        block_pool_ui_object.delete_pool(pool_name)
