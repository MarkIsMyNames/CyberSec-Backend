from __future__ import annotations

import http
import httpx
import pytest

from tests.integration.conftest import (
    auth_headers,
    delete_user,
    full_auth,
    req,
    B64_32,
)


class TestGroups:
    def test_create_group(self, client: httpx.Client, auth: dict):
        resp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(auth["access_token"]),
            json={"name": "mygroup"},
        )
        assert resp.status_code == http.HTTPStatus.CREATED
        assert "id" in resp.json()

    def test_create_group_unauthenticated(self, client: httpx.Client):
        resp = req(client, "POST", "/api/v1/groups/", json={"name": "x"})
        assert resp.status_code == http.HTTPStatus.UNAUTHORIZED

    def test_create_group_missing_fields(self, client: httpx.Client, auth: dict):
        resp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(auth["access_token"]),
            json={},
        )
        assert resp.status_code == http.HTTPStatus.UNPROCESSABLE_ENTITY

    def test_list_groups(self, client: httpx.Client, auth: dict):
        resp = req(
            client,
            "GET",
            "/api/v1/groups/",
            headers=auth_headers(auth["access_token"]),
        )
        assert resp.status_code == http.HTTPStatus.OK

    def test_list_groups_unauthenticated(self, client: httpx.Client):
        resp = req(client, "GET", "/api/v1/groups/")
        assert resp.status_code == http.HTTPStatus.UNAUTHORIZED

    def test_get_group(self, client: httpx.Client, auth: dict):
        grp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(auth["access_token"]),
            json={"name": "getme"},
        ).json()
        resp = req(
            client,
            "GET",
            "/api/v1/groups/%d" % grp["id"],
            headers=auth_headers(auth["access_token"]),
        )
        assert resp.status_code == http.HTTPStatus.OK
        assert resp.json()["id"] == grp["id"]

    def test_get_group_unknown(self, client: httpx.Client, auth: dict):
        resp = req(
            client,
            "GET",
            "/api/v1/groups/999999999",
            headers=auth_headers(auth["access_token"]),
        )
        assert resp.status_code == http.HTTPStatus.NOT_FOUND

    def test_get_group_non_member(self, client: httpx.Client, second_user: dict):
        grp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(second_user["access_token"]),
            json={"name": "nonmembergrp"},
        ).json()
        outsider = full_auth(client)
        resp = req(
            client,
            "GET",
            "/api/v1/groups/%d" % grp["id"],
            headers=auth_headers(outsider["access_token"]),
        )
        assert resp.status_code == http.HTTPStatus.FORBIDDEN
        delete_user(client, outsider["access_token"])

    def test_add_member(self, client: httpx.Client, auth: dict, second_user: dict):
        grp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(auth["access_token"]),
            json={"name": "addmember"},
        ).json()
        lookup = req(
            client,
            "GET",
            "/api/v1/keys/lookup/by-username",
            headers=auth_headers(auth["access_token"]),
            params={"username": second_user["username"]},
        )
        if lookup.status_code != http.HTTPStatus.OK:
            pytest.skip("second_user has no bundle")
        second_id = lookup.json()["user_id"]
        resp = req(
            client,
            "POST",
            "/api/v1/groups/%d/members" % grp["id"],
            headers=auth_headers(auth["access_token"]),
            json={"user_id": second_id, "skdm_ciphertext": B64_32},
        )
        assert resp.status_code == http.HTTPStatus.NO_CONTENT

    def test_add_member_non_member_request(
        self, client: httpx.Client, second_user: dict
    ):
        grp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(second_user["access_token"]),
            json={"name": "nomemreq"},
        ).json()
        outsider = full_auth(client)
        resp = req(
            client,
            "POST",
            "/api/v1/groups/%d/members" % grp["id"],
            headers=auth_headers(outsider["access_token"]),
            json={"user_id": 1, "skdm_ciphertext": B64_32},
        )
        assert resp.status_code == http.HTTPStatus.FORBIDDEN
        delete_user(client, outsider["access_token"])

    def test_add_member_unknown_group(self, client: httpx.Client, auth: dict):
        resp = req(
            client,
            "POST",
            "/api/v1/groups/999999999/members",
            headers=auth_headers(auth["access_token"]),
            json={"user_id": 1, "skdm_ciphertext": B64_32},
        )
        assert resp.status_code == http.HTTPStatus.NOT_FOUND

    def test_remove_member(self, client: httpx.Client, auth: dict, second_user: dict):
        grp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(auth["access_token"]),
            json={"name": "removeme"},
        ).json()
        lookup = req(
            client,
            "GET",
            "/api/v1/keys/lookup/by-username",
            headers=auth_headers(auth["access_token"]),
            params={"username": second_user["username"]},
        )
        if lookup.status_code != http.HTTPStatus.OK:
            pytest.skip("second_user has no bundle")
        second_id = lookup.json()["user_id"]
        req(
            client,
            "POST",
            "/api/v1/groups/%d/members" % grp["id"],
            headers=auth_headers(auth["access_token"]),
            json={"user_id": second_id, "skdm_ciphertext": B64_32},
        )
        resp = req(
            client,
            "DELETE",
            "/api/v1/groups/%d/members/%d" % (grp["id"], second_id),
            headers=auth_headers(auth["access_token"]),
        )
        assert resp.status_code == http.HTTPStatus.NO_CONTENT

    def test_send_group_message(self, client: httpx.Client, auth: dict):
        grp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(auth["access_token"]),
            json={"name": "msggrp"},
        ).json()
        resp = req(
            client,
            "POST",
            "/api/v1/groups/%d/messages" % grp["id"],
            headers=auth_headers(auth["access_token"]),
            json={"epoch": 0, "ciphertext": B64_32},
        )
        assert resp.status_code == http.HTTPStatus.CREATED

    def test_send_group_message_non_member(
        self, client: httpx.Client, second_user: dict
    ):
        grp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(second_user["access_token"]),
            json={"name": "nonmembermsgrp"},
        ).json()
        outsider = full_auth(client)
        resp = req(
            client,
            "POST",
            "/api/v1/groups/%d/messages" % grp["id"],
            headers=auth_headers(outsider["access_token"]),
            json={"epoch": 0, "ciphertext": B64_32},
        )
        assert resp.status_code == http.HTTPStatus.FORBIDDEN
        delete_user(client, outsider["access_token"])

    def test_send_group_message_missing_fields(self, client: httpx.Client, auth: dict):
        grp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(auth["access_token"]),
            json={"name": "missfieldgrp"},
        ).json()
        resp = req(
            client,
            "POST",
            "/api/v1/groups/%d/messages" % grp["id"],
            headers=auth_headers(auth["access_token"]),
            json={},
        )
        assert resp.status_code == http.HTTPStatus.UNPROCESSABLE_ENTITY

    def test_list_group_messages(self, client: httpx.Client, auth: dict):
        grp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(auth["access_token"]),
            json={"name": "listmsggrp"},
        ).json()
        resp = req(
            client,
            "GET",
            "/api/v1/groups/%d/messages" % grp["id"],
            headers=auth_headers(auth["access_token"]),
        )
        assert resp.status_code == http.HTTPStatus.OK
        assert isinstance(resp.json(), list)

    def test_list_group_messages_unauthenticated(
        self, client: httpx.Client, auth: dict
    ):
        grp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(auth["access_token"]),
            json={"name": "unauthlistgrp"},
        ).json()
        resp = req(client, "GET", "/api/v1/groups/%d/messages" % grp["id"])
        assert resp.status_code == http.HTTPStatus.UNAUTHORIZED

    def test_list_group_messages_non_member(
        self, client: httpx.Client, second_user: dict
    ):
        grp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(second_user["access_token"]),
            json={"name": "nonmemlistgrp"},
        ).json()
        outsider = full_auth(client)
        resp = req(
            client,
            "GET",
            "/api/v1/groups/%d/messages" % grp["id"],
            headers=auth_headers(outsider["access_token"]),
        )
        assert resp.status_code == http.HTTPStatus.FORBIDDEN
        delete_user(client, outsider["access_token"])

    def test_delete_group_message(self, client: httpx.Client, auth: dict):
        grp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(auth["access_token"]),
            json={"name": "delmsggrp"},
        ).json()
        msg = req(
            client,
            "POST",
            "/api/v1/groups/%d/messages" % grp["id"],
            headers=auth_headers(auth["access_token"]),
            json={"epoch": 0, "ciphertext": B64_32},
        ).json()
        resp = req(
            client,
            "DELETE",
            "/api/v1/groups/%d/messages/%d" % (grp["id"], msg["id"]),
            headers=auth_headers(auth["access_token"]),
        )
        assert resp.status_code == http.HTTPStatus.NO_CONTENT

    def test_delete_group_message_wrong_owner(
        self, client: httpx.Client, auth: dict, second_user: dict
    ):
        grp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(auth["access_token"]),
            json={"name": "wrongowngrp"},
        ).json()
        msg = req(
            client,
            "POST",
            "/api/v1/groups/%d/messages" % grp["id"],
            headers=auth_headers(auth["access_token"]),
            json={"epoch": 0, "ciphertext": B64_32},
        ).json()
        lookup = req(
            client,
            "GET",
            "/api/v1/keys/lookup/by-username",
            headers=auth_headers(auth["access_token"]),
            params={"username": second_user["username"]},
        )
        if lookup.status_code != http.HTTPStatus.OK:
            pytest.skip("second_user has no bundle")
        second_id = lookup.json()["user_id"]
        req(
            client,
            "POST",
            "/api/v1/groups/%d/members" % grp["id"],
            headers=auth_headers(auth["access_token"]),
            json={"user_id": second_id, "skdm_ciphertext": B64_32},
        )
        resp = req(
            client,
            "DELETE",
            "/api/v1/groups/%d/messages/%d" % (grp["id"], msg["id"]),
            headers=auth_headers(second_user["access_token"]),
        )
        assert resp.status_code in (http.HTTPStatus.FORBIDDEN, http.HTTPStatus.NOT_FOUND)

    def test_delete_group_message_nonexistent(self, client: httpx.Client, auth: dict):
        grp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(auth["access_token"]),
            json={"name": "nonexistmsggrp"},
        ).json()
        resp = req(
            client,
            "DELETE",
            "/api/v1/groups/%d/messages/999999999" % grp["id"],
            headers=auth_headers(auth["access_token"]),
        )
        assert resp.status_code in (http.HTTPStatus.NOT_FOUND, http.HTTPStatus.FORBIDDEN)

    def test_group_message_receipt(
        self, client: httpx.Client, auth: dict, second_user: dict
    ):
        grp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(auth["access_token"]),
            json={"name": "receiptgrp"},
        ).json()
        lookup = req(
            client,
            "GET",
            "/api/v1/keys/lookup/by-username",
            headers=auth_headers(auth["access_token"]),
            params={"username": second_user["username"]},
        )
        if lookup.status_code != http.HTTPStatus.OK:
            pytest.skip("second_user has no bundle")
        second_id = lookup.json()["user_id"]
        req(
            client,
            "POST",
            "/api/v1/groups/%d/members" % grp["id"],
            headers=auth_headers(auth["access_token"]),
            json={"user_id": second_id, "skdm_ciphertext": B64_32},
        )
        msg = req(
            client,
            "POST",
            "/api/v1/groups/%d/messages" % grp["id"],
            headers=auth_headers(auth["access_token"]),
            json={"epoch": 0, "ciphertext": B64_32},
        ).json()
        resp = req(
            client,
            "POST",
            "/api/v1/groups/%d/messages/%d/receipt" % (grp["id"], msg["id"]),
            headers=auth_headers(second_user["access_token"]),
        )
        assert resp.status_code == http.HTTPStatus.NO_CONTENT

    def test_group_message_receipt_nonexistent(self, client: httpx.Client, auth: dict):
        grp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(auth["access_token"]),
            json={"name": "receiptnoexist"},
        ).json()
        resp = req(
            client,
            "POST",
            "/api/v1/groups/%d/messages/999999999/receipt" % grp["id"],
            headers=auth_headers(auth["access_token"]),
        )
        assert resp.status_code == http.HTTPStatus.NOT_FOUND

    def test_send_and_get_skdm(
        self, client: httpx.Client, auth: dict, second_user: dict
    ):
        grp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(auth["access_token"]),
            json={"name": "skdmgrp"},
        ).json()
        lookup = req(
            client,
            "GET",
            "/api/v1/keys/lookup/by-username",
            headers=auth_headers(auth["access_token"]),
            params={"username": second_user["username"]},
        )
        if lookup.status_code != http.HTTPStatus.OK:
            pytest.skip("second_user has no bundle")
        second_id = lookup.json()["user_id"]
        req(
            client,
            "POST",
            "/api/v1/groups/%d/members" % grp["id"],
            headers=auth_headers(auth["access_token"]),
            json={"user_id": second_id, "skdm_ciphertext": B64_32},
        )
        send_resp = req(
            client,
            "POST",
            "/api/v1/groups/%d/skdm" % grp["id"],
            headers=auth_headers(auth["access_token"]),
            json={str(second_id): B64_32},
        )
        assert send_resp.status_code == http.HTTPStatus.NO_CONTENT
        get_resp = req(
            client,
            "GET",
            "/api/v1/groups/%d/skdm" % grp["id"],
            headers=auth_headers(second_user["access_token"]),
        )
        assert get_resp.status_code == http.HTTPStatus.OK

    def test_get_skdm_none_exists(self, client: httpx.Client, auth: dict):
        grp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(auth["access_token"]),
            json={"name": "noskdmgrp"},
        ).json()
        resp = req(
            client,
            "GET",
            "/api/v1/groups/%d/skdm" % grp["id"],
            headers=auth_headers(auth["access_token"]),
        )
        assert resp.status_code in (http.HTTPStatus.OK, http.HTTPStatus.NOT_FOUND)

    def test_send_skdm_non_member(self, client: httpx.Client, second_user: dict):
        grp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(second_user["access_token"]),
            json={"name": "skdmnonmem"},
        ).json()
        outsider = full_auth(client)
        resp = req(
            client,
            "POST",
            "/api/v1/groups/%d/skdm" % grp["id"],
            headers=auth_headers(outsider["access_token"]),
            json={"1": B64_32},
        )
        assert resp.status_code == http.HTTPStatus.FORBIDDEN
        delete_user(client, outsider["access_token"])

    def test_get_skdm_non_member(self, client: httpx.Client, second_user: dict):
        grp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(second_user["access_token"]),
            json={"name": "getskdmnonmem"},
        ).json()
        outsider = full_auth(client)
        resp = req(
            client,
            "GET",
            "/api/v1/groups/%d/skdm" % grp["id"],
            headers=auth_headers(outsider["access_token"]),
        )
        assert resp.status_code == http.HTTPStatus.FORBIDDEN
        delete_user(client, outsider["access_token"])

    def test_delete_creator_reassigns_creator(
        self, client: httpx.Client, second_user: dict
    ):
        creator = full_auth(client)
        grp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(creator["access_token"]),
            json={"name": "reassigntest"},
        ).json()
        lookup = req(
            client,
            "GET",
            "/api/v1/keys/lookup/by-username",
            headers=auth_headers(creator["access_token"]),
            params={"username": second_user["username"]},
        )
        if lookup.status_code != http.HTTPStatus.OK:
            pytest.skip("second_user has no bundle")
        second_id = lookup.json()["user_id"]
        req(
            client,
            "POST",
            "/api/v1/groups/%d/members" % grp["id"],
            headers=auth_headers(creator["access_token"]),
            json={"user_id": second_id, "skdm_ciphertext": B64_32},
        )
        req(
            client,
            "DELETE",
            "/api/v1/auth/me",
            headers=auth_headers(creator["access_token"]),
        )
        resp = req(
            client,
            "GET",
            "/api/v1/groups/%d" % grp["id"],
            headers=auth_headers(second_user["access_token"]),
        )
        assert resp.status_code == http.HTTPStatus.OK, "group should still exist after creator deleted"

    def test_delete_sole_member_creator_deletes_group(
        self, client: httpx.Client, second_user: dict
    ):
        creator = full_auth(client)
        grp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(creator["access_token"]),
            json={"name": "solecreatortest"},
        ).json()
        req(
            client,
            "DELETE",
            "/api/v1/auth/me",
            headers=auth_headers(creator["access_token"]),
        )
        resp = req(
            client,
            "GET",
            "/api/v1/groups/%d" % grp["id"],
            headers=auth_headers(second_user["access_token"]),
        )
        assert resp.status_code in (http.HTTPStatus.NOT_FOUND, http.HTTPStatus.FORBIDDEN)

    def test_delete_user_increments_group_epoch(
        self, client: httpx.Client, auth: dict, second_user: dict
    ):
        grp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(auth["access_token"]),
            json={"name": "epochtest"},
        ).json()
        lookup = req(
            client,
            "GET",
            "/api/v1/keys/lookup/by-username",
            headers=auth_headers(auth["access_token"]),
            params={"username": second_user["username"]},
        )
        if lookup.status_code != http.HTTPStatus.OK:
            pytest.skip("second_user has no bundle")
        second_id = lookup.json()["user_id"]
        req(
            client,
            "POST",
            "/api/v1/groups/%d/members" % grp["id"],
            headers=auth_headers(auth["access_token"]),
            json={"user_id": second_id, "skdm_ciphertext": B64_32},
        )
        epoch_before = req(
            client,
            "GET",
            "/api/v1/groups/%d" % grp["id"],
            headers=auth_headers(auth["access_token"]),
        ).json()["epoch"]
        user_c = full_auth(client)
        user_c_lookup = req(
            client,
            "GET",
            "/api/v1/keys/lookup/by-username",
            headers=auth_headers(auth["access_token"]),
            params={"username": user_c["username"]},
        )
        if user_c_lookup.status_code == http.HTTPStatus.OK:
            user_c_id = user_c_lookup.json()["user_id"]
            req(
                client,
                "POST",
                "/api/v1/groups/%d/members" % grp["id"],
                headers=auth_headers(auth["access_token"]),
                json={"user_id": user_c_id, "skdm_ciphertext": B64_32},
            )
        req(
            client,
            "DELETE",
            "/api/v1/auth/me",
            headers=auth_headers(user_c["access_token"]),
        )
        epoch_after = req(
            client,
            "GET",
            "/api/v1/groups/%d" % grp["id"],
            headers=auth_headers(second_user["access_token"]),
        ).json()["epoch"]
        assert epoch_after > epoch_before

    def test_all_group_endpoints_unauthenticated(
        self, client: httpx.Client, auth: dict
    ):
        grp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(auth["access_token"]),
            json={"name": "unauthallgrp"},
        ).json()
        gid = grp["id"]
        endpoints = [
            ("GET", "/api/v1/groups/"),
            ("POST", "/api/v1/groups/"),
            ("GET", "/api/v1/groups/%d" % gid),
            ("POST", "/api/v1/groups/%d/members" % gid),
            ("GET", "/api/v1/groups/%d/messages" % gid),
            ("POST", "/api/v1/groups/%d/messages" % gid),
            ("POST", "/api/v1/groups/%d/skdm" % gid),
            ("GET", "/api/v1/groups/%d/skdm" % gid),
        ]
        for method, path in endpoints:
            resp = req(client, method, path)
            assert resp.status_code == http.HTTPStatus.UNAUTHORIZED, "Expected 401 on %s %s" % (method, path)
