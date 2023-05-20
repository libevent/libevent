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
    p.add_argument('revision_range')
    return p.parse_args()

def main():
    opts = parse_opts()
    repo = git.Repo(opts.git_root)
    squash = not opts.no_squash_merge_childs

    ignore = []

    revision_range = opts.revision_range
    if not revision_range:
        revision_range = repo.git.describe('--abbrev=0') + '..'

    for commit in repo.iter_commits(revision_range):
        authors = set({commit.author})
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
        print(opts.format % {
            's': commit.summary,
            'h': commit.hexsha[:opts.abbrev],
            # TODO: use GitHub API to extract github user names
            'aN': ', '.join(map(str, authors)),
        })


if __name__ == "__main__":
    main()
