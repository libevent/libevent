#!/usr/bin/env python3

import git
import argparse

def parse_opts():
    p = argparse.ArgumentParser()
    p.add_argument('--git-root', default='.')
    p.add_argument('--no-squash-merge-childs', action='store_true')
    p.add_argument('--abbrev', default=8, type=int)
    # git config pretty.le
    p.add_argument('--format', default='  o %(s)s (%(h)s %(aN)s)')
    # I did not find a way to search PRs by commits (even though web can do
    # this), so instead, you should configure your repository to fetch all PRs,
    # like this:
    #
    #   [remote "upstream"]
    #     url = git@github.com:libevent/libevent
    #     fetch = +refs/heads/*:refs/remotes/upstream/*
    #     fetch = +refs/pull/*/head:refs/remotes/upstream/pr/*
    #
    # So that the script could obtain the PR number.
    #
    # I hope that it will work with rebase & squashes.
    p.add_argument('--pull-request-refs', default='upstream/pr/')
    p.add_argument('revision_range')
    return p.parse_args()

def main():
    opts = parse_opts()
    repo = git.Repo(opts.git_root)
    squash = not opts.no_squash_merge_childs

    changelog = []
    ignore = []

    revision_range = opts.revision_range
    if not revision_range:
        revision_range = repo.git.describe('--abbrev=0') + '..'

    refs = repo.references
    prs = dict()
    for ref in refs:
        if not ref.name.startswith(opts.pull_request_refs):
            continue
        prs[ref.commit] = ref.name[len(opts.pull_request_refs):]

    for commit in repo.iter_commits(revision_range):
        authors = set({commit.author})
        pr = prs.get(commit, None)
        if squash:
            if commit.hexsha in ignore:
                continue
            if len(commit.parents) > 1:
                # reset authors, since we do not want to take any credits to
                # the merger
                authors.clear()
                for c in repo.iter_commits('{}..{}'.format(*commit.parents)):
                    ignore.append(c.hexsha)
                    authors.add(c.author)
                    pr = prs.get(c, pr)
        summary = commit.summary
        if pr is not None:
            pr = f'#{pr}'
            if pr not in summary:
                summary += f' ({pr})'
        changelog.append(opts.format % {
            's': summary,
            'h': commit.hexsha[:opts.abbrev],
            # TODO: use GitHub API to extract github user names
            'aN': ', '.join(map(str, authors)),
        })

    # NOTE: You cannot use repo.iter_commits(reverse=True) because this will
    # break squashing
    changelog.reverse()
    for entry in changelog:
        print(entry)

if __name__ == "__main__":
    main()
