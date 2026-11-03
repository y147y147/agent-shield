from pathlib import Path

from agent_shield.envfile import load_dotenv


def test_load_dotenv_sets_missing_only(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("FOO_TEST_KEY=from-file\nBAR_TEST_KEY=keep-me\n", encoding="utf-8")
    monkeypatch.delenv("FOO_TEST_KEY", raising=False)
    monkeypatch.setenv("BAR_TEST_KEY", "already")
    monkeypatch.chdir(tmp_path)
    assert load_dotenv() == Path.cwd() / ".env"
    import os

    assert os.environ["FOO_TEST_KEY"] == "from-file"
    assert os.environ["BAR_TEST_KEY"] == "already"
