#!/usr/bin/env python3

import git
import argparse
import re

def parse_opts():
    p = argparse.ArgumentParser()
    p.add_argument('--git-root', default='.')
    p.add_argument('--no-squash-merge-childs', action='store_true')
    p.add_argument('--abbrev', default=8, type=int)
    # git config pretty.le
    p.add_argument('--format', default='  o %(s)s (%(h)s %(aN)s)')
    p.add_argument('--revision-range')
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
        if squash:
            if commit.hexsha in ignore:
                continue
            if len(commit.parents) > 1:
                for c in repo.iter_commits('{}..{}'.format(*commit.parents)):
                    ignore.append(c.hexsha)
        print(opts.format % {
            's': commit.summary,
            'h': commit.hexsha[:opts.abbrev],
            'aN': str(commit.author),
        })


if __name__ == "__main__":
    main()
