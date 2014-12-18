import json
import github3

def github_set_ref(repo, ref, sha, force=False):
    url = repo._build_url('git', 'refs', ref, base_url=repo._api)
    data = {'sha': sha, 'force': force}

    js = repo._json(repo._patch(url, data=json.dumps(data)), 200)

    return github3.git.Reference(js, repo) if js else None
