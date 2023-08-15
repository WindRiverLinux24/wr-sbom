#!/usr/bin/env python3
import lxsbomtool
import unittest

class MockLogger:
    def debug(self, message):
        self.message = message + "mocked"

class LogTimedEventTest(unittest.TestCase):
    def test_time_false(self):
        common_args = lxsbomtool.CommonArgs(MockLogger(), None, None, None, None)
        lxsbomtool.logTimedEvent("running logger call", 0, False, common_args)
        self.assertEquals(common_args.getLogger().message, "Completed substask running logger callmocked")

class TestDocrefMapping(unittest.TestCase):
    def test_single_matching(self):
        image_json = [{ "externalDocumentId": "example_docref", "spdxDocument": "example_spdx" }]
        index_json = { "documents": [{ "documentNamespace": "example_spdx", "filename": "example.file" }] }
        docref_dict = lxsbomtool.make_document_ref_dict(image_json, index_json)

        self.assertEquals(docref_dict["example_docref"], "example.file")

    def test_multiple_matching(self):
        image_json = [
            { "externalDocumentId": "example_docref", "spdxDocument": "example_spdx" },
            { "externalDocumentId": "example_docref2", "spdxDocument": "example_spdx2" }
        ]
        index_json = { "documents": [
            { "documentNamespace": "example_spdx", "filename": "example.file" },
            { "documentNamespace": "example_spdx2", "filename": "example2.file" }
        ] }
        docref_dict = lxsbomtool.make_document_ref_dict(image_json, index_json)

        self.assertEquals(docref_dict["example_docref"], "example.file")
        self.assertEquals(docref_dict["example_docref2"], "example2.file")

    def test_duplicate_skips(self):
        image_json = [
            { "externalDocumentId": "example_docref", "spdxDocument": "example_spdx" },
            { "externalDocumentId": "example_docref", "spdxDocument": "example_spdx2" }
        ]
        index_json = { "documents": [
            { "documentNamespace": "example_spdx", "filename": "example.file" },
            { "documentNamespace": "example_spdx2", "filename": "example2.file" }
        ] }
        docref_dict = lxsbomtool.make_document_ref_dict(image_json, index_json)

        # Make sure that if there is a duplicate entry, only the first one is
        # placed in the dict to match the original functionality.
        self.assertEquals(docref_dict["example_docref"], "example.file")

if __name__ == "__main__":
    unittest.main()

