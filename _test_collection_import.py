#!/usr/bin/env python3
"""Tests deduplicación de colección Postman/OpenAPI."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from security.collection_import import dedupe_collection_endpoints, parse_api_collection


def test_dedupe_relative_and_absolute_url():
    eps = [
        {
            "method": "GET",
            "path": "/api/card",
            "url": "/api/card",
            "source": "collection:postman",
        },
        {
            "method": "GET",
            "path": "/api/card",
            "url": "https://api.example.com/api/card",
            "source": "collection:postman",
        },
    ]
    out = dedupe_collection_endpoints(eps)
    assert len(out) == 1
    assert out[0]["url"].startswith("https://")


def test_postman_folder_not_double_counted():
    data = {
        "info": {"schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": [
            {
                "name": "Folder",
                "item": [
                    {
                        "name": "Health",
                        "request": {
                            "method": "GET",
                            "url": "{{baseUrl}}/health",
                        },
                    }
                ],
            }
        ],
    }
    eps, _ = parse_api_collection(data, "https://api.example.com")
    assert len(eps) == 1
    assert eps[0]["method"] == "GET"
    assert "health" in eps[0]["path"]


if __name__ == "__main__":
    test_dedupe_relative_and_absolute_url()
    test_postman_folder_not_double_counted()
    print("ok")
