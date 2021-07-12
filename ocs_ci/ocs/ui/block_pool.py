import logging
import time

from ocs_ci.ocs.ui.base_ui import PageNavigator
from ocs_ci.ocs.ui.views import locators
from ocs_ci.utility.utils import get_ocp_version, get_running_ocp_version
from selenium.webdriver.common.by import By



logger = logging.getLogger(__name__)


class BlockPoolUI(PageNavigator):
    """
    User Interface Selenium

    """

    def __init__(self, driver):
        super().__init__(driver)
        ocp_version = get_ocp_version()
        self.bp_loc = locators[ocp_version]["block_pool"]

    def create_pool(self, pool_name, replica, compression):
        self.navigate_block_pool_page()
        self.do_click(self.bp_loc["create_block_pool"])
        self.do_send_keys(self.bp_loc["new_pool_name"], pool_name)
        self.do_click(self.bp_loc["first_select_replica"])
        self.do_click(self.bp_loc["second_select_replica_2"])
        self.do_click(self.bp_loc["conpression_checkbox"])
        self.do_click(self.bp_loc["pool_confirm_create"])

    def delete_pool(self, pool_name):
        self.navigate_block_pool_page()
        self.do_click((f"{pool_name}", By.LINK_TEXT))
        self.do_click(self.bp_loc["actions_inside_pool"])
        self.do_click(self.bp_loc["delete_pool_inside_pool"])
        self.do_click(self.bp_loc["confirm_delete_inside_pool"])

    def check_pool_existence(self, pool_name):
        self.navigate_block_pool_page()
        time.sleep(5)
        pool_existence = self.check_element_text(expected_text=pool_name)
        logger.info(f"Pool name {pool_name} is {pool_existence}")




