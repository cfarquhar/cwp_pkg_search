import json
import os
import re
import requests
import urllib3

PAGE_SIZE = 50
RETRY_LIMIT = 1
VERIFY_TLS = not os.environ.get("TLS_INSECURE", False)

CWP_API = f"{os.environ.get('CWP_CONSOLE_PATH')}/api/v1"
CWP_USER = os.environ.get("CWP_USER")
CWP_PASSWORD = os.environ.get("CWP_PASSWORD")


class CwpApi:
    def __init__(self, endpoint=CWP_API, user=CWP_USER, password=CWP_PASSWORD):
        self.endpoint = endpoint
        self.user = user
        self.password = password
        self.verify_tls = VERIFY_TLS

        self._global_headers = {}

        # Avoid cluttering output if TLS verify is False
        if not self.verify_tls:
            urllib3.disable_warnings()

        self.token = self.get_token()

    def _retry(times=RETRY_LIMIT):
        def decorator(func):
            def newfn(*args, **kwargs):
                self = args[0]
                attempt = 1
                while attempt <= times:
                    try:
                        return func(*args, **kwargs)
                    except Exception as e:
                        if e.response.status_code == 401:
                            self.get_token()
                            attempt += 1
                            continue
                        print(
                            f"Encountered exception during {func}.  Attempt {attempt} of {times}"
                        )
                        attempt += 1
                return func(*args, **kwargs)

            return newfn

        return decorator

    def get_token(self):
        body = {"username": self.user, "password": self.password}
        r = requests.post(
            f"{self.endpoint}/authenticate", json=body, verify=self.verify_tls
        )
        if r.status_code != 200:
            raise Exception(
                f"Unable to authenticate to {CWP_API} with provided credentials."
            )
        r.raise_for_status()
        token = r.json()["token"]
        self._global_headers = {"Authorization": f"Bearer {token}"}
        return token

    @_retry()
    def get_images(self, headers={}, params={}):
        r_headers = self._global_headers | headers
        r = requests.get(
            f"{self.endpoint}/images",
            headers=r_headers,
            params=params,
            verify=self.verify_tls,
        )
        r.raise_for_status()
        return r.json()

    def get_all_images(self):
        done = False
        results = []
        params = {"offset": 0, "limit": PAGE_SIZE}
        while not done:
            images = self.get_images(params=params)
            results += images
            params["offset"] += PAGE_SIZE
            if len(images) < PAGE_SIZE:
                done = True
        return results

    def get_images_with_pkg(self, pkg_re=".*", version_re=".*"):
        results = []
        images = client.get_all_images()
        for image in images:
            id = image["_id"]
            repo_tag = image["repoTag"]
            name = f"{repo_tag['registry']}/{repo_tag['repo']}:{repo_tag['tag']}"
            result = {"id": id, "name": name, "packages": []}
            for pkg_set in image["packages"]:
                pkg_type = pkg_set["pkgsType"]
                for pkg in pkg_set["pkgs"]:
                    pkg_name = pkg["name"]
                    pkg_ver = pkg["version"]
                    if re.match(pkg_re, pkg_name) and re.match(version_re, pkg_ver):
                        result["packages"].append(
                            {"name": pkg_name, "version": pkg_ver, "type": pkg_type}
                        )
            if result["packages"]:
                results.append(result)
        return results


if __name__ == "__main__":
    client = CwpApi()
    results = client.get_images_with_pkg(pkg_re=".*log4j.*")
    print(json.dumps(results))
