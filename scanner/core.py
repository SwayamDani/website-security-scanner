import logging
from scanner.utils.reporting import generate_report

class Scanner:
    def __init__(self, domain):
        self.domain = domain
        self.modules = []  # List of module instances
        self.results = []  # Collected results

        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Initialized scanner for {self.domain}")

    def register_module(self, module_instance):
        """
        Register a test module (object) to the scanner.
        """
        self.modules.append(module_instance)
        self.logger.info(f"Registered module: {module_instance.__class__.__name__}")

    def run(self):
        """
        Run all registered modules and collect results.
        """
        self.logger.info("Starting scan...")

        for module in self.modules:
            self.logger.info(f"Running module: {module.__class__.__name__}")
            try:
                result = module.run_test(self.domain)
                self.results.append(result)
            except Exception as e:
                self.logger.error(f"Module {module.__class__.__name__} failed: {e}")

        # Generate final report
        generate_report(self.domain, self.results)

        self.logger.info("Scan completed.")
