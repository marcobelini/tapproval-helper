"""Codex image replies reach the existing authenticated watch image route."""
import base64
import json
import tempfile
import unittest
from pathlib import Path

import codex_sessions
import watch_dashboard

PNG = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=')


class CodexImagesTests(unittest.TestCase):
    def test_assistant_markdown_image_reaches_watch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / 'proposal.png'
            image.write_bytes(PNG)
            rollout = root / 'rollout.jsonl'
            rows = [
                {'type': 'session_meta', 'payload': {'id': 'image-test', 'cwd': directory}},
                {'type': 'response_item', 'payload': {'type': 'message', 'role': 'assistant',
                 'content': [{'type': 'output_text', 'text': f'Proposal A\n![Quiet row]({image})'}]}}
            ]
            rollout.write_text(''.join(json.dumps(row) + '\n' for row in rows))
            turn = codex_sessions.thread_info(str(rollout))['turns'][0]
            self.assertEqual(len(turn.get('images', [])), 1)
            ref = turn['images'][0]
            self.assertEqual(base64.b64decode(watch_dashboard._IMAGES[ref][1]), PNG)

    def test_only_project_images_outside_code_are_attached(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / 'project'
            project.mkdir()
            (root / 'private.png').write_bytes(PNG)
            try:
                (project / 'escape.png').symlink_to(root / 'private.png')
            except OSError:
                pass  # Windows may require an elevated account for symlinks.
            (project / 'valid.png').write_bytes(PNG)
            text = (f'![private]({root}/private.png)\n![escape]({project}/escape.png)\n'
                    '![remote](https://example.com/picture.png)\n'
                    '```md\n![example](valid.png)\n```')
            self.assertEqual(codex_sessions._reply_images(text, str(project)), [])
            self.assertEqual(len(codex_sessions._reply_images('![A](valid.png)', str(project))), 1)

    def test_missing_invalid_and_oversized_are_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'invalid.png').write_text('private text')
            with (root / 'large.png').open('wb') as handle:
                handle.write(PNG)
                handle.truncate(watch_dashboard.IMAGE_MAX_BYTES + 1)
            self.assertEqual(codex_sessions._reply_images(
                '![a](missing.png) ![b](invalid.png) ![c](large.png)', directory), [])


if __name__ == '__main__':
    unittest.main()
