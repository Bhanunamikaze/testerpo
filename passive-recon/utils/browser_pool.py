"""
Browser Pool Manager
====================

Manages multiple Playwright browser sessions with tab pooling for concurrent operations.
Each browser can have 10-15 tabs running queries simultaneously.
"""

import asyncio
import logging
import random
from typing import List, Dict, Optional
from contextlib import asynccontextmanager


logger = logging.getLogger(__name__)


class BrowserPool:
    """
    Manages pool of Playwright browser instances with multiple tabs each.
    Enables high-concurrency search operations while managing resources.
    """

    def __init__(self, config: Dict):
        """
        Initialize browser pool.

        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.browser_count = config.get('browser_count', 3)
        self.tabs_per_browser = config.get('tabs_per_browser', 12)
        self.headless = config.get('headless', True)
        self.browsers = []
        self.contexts = []
        self.playwright = None

    async def initialize(self):
        """Initialize Playwright and create browser instances."""
        try:
            from playwright.async_api import async_playwright

            logger.info(f"Initializing {self.browser_count} browser sessions...")

            self.playwright = await async_playwright().start()

            # Create browser instances
            for i in range(self.browser_count):
                browser = await self._create_browser(i)
                self.browsers.append(browser)

            logger.info(f"Browser pool ready: {self.browser_count} browsers × {self.tabs_per_browser} tabs = {self.browser_count * self.tabs_per_browser} concurrent operations")

        except ImportError:
            logger.error("Playwright not installed. Run: pip install playwright && playwright install chromium")
            raise

    async def _create_browser(self, browser_id: int):
        """
        Create a single browser instance with stealth configuration.

        Args:
            browser_id: Unique browser identifier

        Returns:
            Browser instance
        """
        # Random user agent pool
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        ]

        # Randomize viewport sizes
        viewports = [
            {'width': 1920, 'height': 1080},
            {'width': 1366, 'height': 768},
            {'width': 1536, 'height': 864},
            {'width': 1440, 'height': 900},
        ]

        browser_type = self.playwright.chromium

        browser = await browser_type.launch(
            headless=self.headless,
            args=[
                '--disable-blink-features=AutomationControlled',
                '--disable-dev-shm-usage',
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-web-security',
                '--disable-features=IsolateOrigins,site-per-process',
                '--disable-gpu',
                f'--window-size={random.choice(viewports)["width"]},{random.choice(viewports)["height"]}',
            ]
        )

        # Create context with stealth settings
        context = await browser.new_context(
            user_agent=random.choice(user_agents),
            viewport=random.choice(viewports),
            locale='en-US',
            timezone_id='America/New_York',
            permissions=[],
            java_script_enabled=True,
            bypass_csp=True,
            ignore_https_errors=True,
        )

        # Add stealth scripts to context
        await context.add_init_script("""
            // Overwrite the `navigator.webdriver` property
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined,
            });

            // Overwrite the `chrome` property
            window.chrome = {
                runtime: {},
            };

            // Overwrite the `permissions` property
            const originalQuery = window.navigator.permissions.query;
            window.navigator.permissions.query = (parameters) => (
                parameters.name === 'notifications' ?
                    Promise.resolve({ state: Notification.permission }) :
                    originalQuery(parameters)
            );

            // Overwrite the `plugins` property
            Object.defineProperty(navigator, 'plugins', {
                get: () => [1, 2, 3, 4, 5],
            });

            // Overwrite the `languages` property
            Object.defineProperty(navigator, 'languages', {
                get: () => ['en-US', 'en'],
            });
        """)

        self.contexts.append({
            'id': browser_id,
            'browser': browser,
            'context': context,
            'tabs': []
        })

        logger.debug(f"Browser {browser_id} created")
        return browser

    @asynccontextmanager
    async def get_page(self, browser_id: Optional[int] = None):
        """
        Context manager to get a page from the pool.

        Args:
            browser_id: Specific browser to use (None for round-robin)

        Yields:
            Playwright page instance
        """
        if browser_id is None:
            browser_id = random.randint(0, self.browser_count - 1)

        context_info = self.contexts[browser_id]
        context = context_info['context']

        # Create new page
        page = await context.new_page()

        # Add random delays to seem more human
        await page.set_extra_http_headers({
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })

        try:
            yield page
        finally:
            await page.close()

    async def execute_concurrent_tasks(self, tasks: List[Dict], max_concurrent: Optional[int] = None):
        """
        Execute tasks concurrently across all browser tabs.

        Args:
            tasks: List of task dictionaries with 'url' and 'callback'
            max_concurrent: Maximum concurrent operations (default: browsers × tabs)

        Returns:
            List of results
        """
        if max_concurrent is None:
            max_concurrent = self.browser_count * self.tabs_per_browser

        semaphore = asyncio.Semaphore(max_concurrent)
        results = []

        async def run_task(task: Dict):
            async with semaphore:
                try:
                    async with self.get_page() as page:
                        result = await task['callback'](page, task)
                        return result
                except Exception as e:
                    logger.error(f"Task failed: {e}")
                    return None

        # Execute all tasks concurrently
        task_results = await asyncio.gather(*[run_task(task) for task in tasks], return_exceptions=True)

        # Filter out None results and exceptions
        results = [r for r in task_results if r is not None and not isinstance(r, Exception)]

        return results

    async def close(self):
        """Close all browsers and cleanup."""
        logger.info("Closing browser pool...")

        for context_info in self.contexts:
            try:
                await context_info['context'].close()
                await context_info['browser'].close()
            except Exception as e:
                logger.warning(f"Error closing browser: {e}")

        if self.playwright:
            await self.playwright.stop()

        logger.info("Browser pool closed")

    async def __aenter__(self):
        """Async context manager entry."""
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()


class TabPool:
    """
    Manages a pool of tabs within a single browser for concurrent operations.
    """

    def __init__(self, context, max_tabs: int = 12):
        """
        Initialize tab pool.

        Args:
            context: Playwright browser context
            max_tabs: Maximum number of tabs
        """
        self.context = context
        self.max_tabs = max_tabs
        self.available_tabs = []
        self.in_use_tabs = set()
        self._lock = asyncio.Lock()

    async def initialize(self):
        """Pre-create tab pool."""
        for _ in range(self.max_tabs):
            page = await self.context.new_page()
            self.available_tabs.append(page)

    async def acquire(self):
        """Acquire a tab from the pool."""
        async with self._lock:
            while not self.available_tabs:
                await asyncio.sleep(0.1)

            page = self.available_tabs.pop()
            self.in_use_tabs.add(page)
            return page

    async def release(self, page):
        """Release a tab back to the pool."""
        async with self._lock:
            if page in self.in_use_tabs:
                self.in_use_tabs.remove(page)

                # Clear page state
                try:
                    await page.goto('about:blank')
                except:
                    # If clearing fails, create a new page
                    await page.close()
                    page = await self.context.new_page()

                self.available_tabs.append(page)

    async def close_all(self):
        """Close all tabs."""
        all_pages = list(self.available_tabs) + list(self.in_use_tabs)
        for page in all_pages:
            try:
                await page.close()
            except:
                pass

    @asynccontextmanager
    async def get_tab(self):
        """Context manager for tab acquisition."""
        page = await self.acquire()
        try:
            yield page
        finally:
            await self.release(page)
