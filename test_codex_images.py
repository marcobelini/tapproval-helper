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
            for index, target in enumerate((str(image), image.as_posix(), image.name)):
                with self.subTest(target=target):
                    rollout = root / ('rollout-%d.jsonl' % index)
                    rows = [
                        {'type': 'session_meta', 'payload': {'id': 'image-test', 'cwd': directory}},
                        {'type': 'response_item', 'payload': {'type': 'message', 'role': 'assistant',
                         'content': [{'type': 'output_text', 'text': f'Proposal A\n![Quiet row]({target})'}]}}
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


class CodexPastedPicturesTests(unittest.TestCase):
    """A picture pasted into a Codex chat is an input_image part holding a
    data: address. The thread dropped it, and a message that was only a
    picture showed nothing (2026-11-17)."""

    def setUp(self):
        watch_dashboard._IMAGES.clear()
        watch_dashboard._IMAGE_ORIGINS.clear()
        codex_sessions._THREADS.clear()
        self._sips = watch_dashboard.SIPS
        watch_dashboard.SIPS = '/nonexistent/sips'

    def tearDown(self):
        watch_dashboard.SIPS = self._sips
        watch_dashboard._IMAGES.clear()
        watch_dashboard._IMAGE_ORIGINS.clear()
        codex_sessions._THREADS.clear()

    @staticmethod
    def _picture(data=PNG, media='image/png'):
        return {'type': 'input_image', 'detail': 'high',
                'image_url': 'data:%s;base64,%s' % (media, base64.b64encode(data).decode())}

    def _turns(self, directory, messages):
        rollout = Path(directory) / 'rollout.jsonl'
        rows = [{'type': 'session_meta', 'payload': {'id': 'paste-test', 'cwd': directory}}]
        rows += [{'type': 'response_item', 'payload': {'type': 'message', 'role': 'user',
                                                       'content': content}}
                 for content in messages]
        rollout.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        return rollout, codex_sessions.thread_info(str(rollout))['turns']

    def test_a_pasted_picture_rides_with_the_words(self):
        with tempfile.TemporaryDirectory() as directory:
            _, turns = self._turns(directory, [
                [{'type': 'input_text', 'text': 'What is wrong here?'}, self._picture()]])
            self.assertEqual(len(turns), 1)
            self.assertEqual(turns[0]['text'], 'What is wrong here?')
            self.assertEqual(len(turns[0]['images']), 1)
            self.assertEqual(watch_dashboard.image_bytes(turns[0]['images'][0]),
                             ('image/png', PNG))

    def test_a_message_that_is_only_a_picture_still_shows(self):
        with tempfile.TemporaryDirectory() as directory:
            _, turns = self._turns(directory, [[self._picture()]])
            self.assertEqual(len(turns), 1)
            self.assertEqual(turns[0]['text'], '[image]')
            self.assertEqual(turns[0]['role'], 'user')
            self.assertEqual(len(turns[0]['images']), 1)

    def test_what_is_not_a_picture_held_in_the_chat_is_left_out(self):
        with tempfile.TemporaryDirectory() as directory:
            _, turns = self._turns(directory, [[
                {'type': 'input_text', 'text': 'Look'},
                {'type': 'input_image', 'image_url': 'https://example.com/a.png'},
                {'type': 'input_image', 'image_url': 'data:text/html;base64,PGI+'},
                {'type': 'input_image', 'image_url': 7},
                {'type': 'input_image'}]])
            self.assertEqual(len(turns), 1)
            self.assertFalse(turns[0].get('images'))

    def test_a_pasted_picture_pushed_out_comes_back(self):
        held = watch_dashboard.IMAGE_CACHE_MAX
        watch_dashboard.IMAGE_CACHE_MAX = 1
        try:
            with tempfile.TemporaryDirectory() as directory:
                other = PNG + b'other'
                _, turns = self._turns(directory, [
                    [{'type': 'input_text', 'text': 'One'}, self._picture()],
                    [{'type': 'input_text', 'text': 'Two'}, self._picture(other)]])
                first = turns[0]['images'][0]
                self.assertNotIn(first, watch_dashboard._IMAGES)
                self.assertEqual(watch_dashboard.image_bytes(first), ('image/png', PNG))
        finally:
            watch_dashboard.IMAGE_CACHE_MAX = held

    def test_a_linked_picture_pushed_out_comes_back(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / 'proposal.png'
            image.write_bytes(PNG)
            rollout = Path(directory) / 'rollout.jsonl'
            rows = [{'type': 'session_meta', 'payload': {'id': 'link-test', 'cwd': directory}},
                    {'type': 'response_item', 'payload': {
                        'type': 'message', 'role': 'assistant',
                        'content': [{'type': 'output_text', 'text': 'A\n![Row](proposal.png)'}]}}]
            rollout.write_text(''.join(json.dumps(row) + '\n' for row in rows))
            ref = codex_sessions.thread_info(str(rollout))['turns'][0]['images'][0]
            watch_dashboard._IMAGES.clear()
            self.assertEqual(watch_dashboard.image_bytes(ref), ('image/png', PNG))
            image.write_bytes(PNG + b'changed since')
            watch_dashboard._IMAGES.clear()
            self.assertIsNone(watch_dashboard.image_bytes(ref))


if __name__ == '__main__':
    unittest.main()
