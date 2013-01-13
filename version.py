#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Douglas Creager <dcreager@dcreager.net>
# This file is placed into the public domain.

# Calculates the current version number.  If possible, this is the
# output of “git describe”, modified to conform to the versioning
# scheme that setuptools uses.  If “git describe” returns an error
# (most likely because we're in an unpacked copy of a release tarball,
# rather than in a git working copy), then we fall back on reading the
# contents of the RELEASE-VERSION file.
#
# To use this script, simply import it your setup.py file, and use the
# results of get_git_version() as your package version:
#
# from version import *
#
# setup(
#     version=get_git_version(),
#     .
#     .
#     .
# )
#
# This will automatically update the RELEASE-VERSION file, if
# necessary.  Note that the RELEASE-VERSION file should *not* be
# checked into git; please add it to your top-level .gitignore file.
#
# You'll probably want to distribute the RELEASE-VERSION file in your
# sdist tarballs; to do this, just create a MANIFEST.in file that
# contains the following line:
#
#   include RELEASE-VERSION

__all__ = ("get_git_version")

from subprocess import Popen, PIPE


def call_git_describe(abbrev=4, commit_hash=None):
    try:
        cmd = ['git', 'describe', '--abbrev=%d' % abbrev]
        if commit_hash:
            cmd.append(commit_hash)
        p = Popen(cmd, stdout=PIPE, stderr=PIPE)
        p.stderr.close()
        line = p.stdout.readlines()[0]
        return line.strip()

    except:
        return None


def get_git_changelog(abbrev=4):
    my_tag = call_git_describe(abbrev)
    prev_tag = None
    prev_tag_commit_hash = None

    # Don't do changelogs for tags with a dash: they are commits between tags
    if '-' in my_tag:
        return None

    # Collect commits
    commits = []

    # Determine the previous version
    try:
        skip = 0
        while True:
            cmd = ['git', 'rev-list', '--tags', '--skip=%d' % skip,
                   '--max-count=1']
            p = Popen(cmd, stdout=PIPE, stderr=PIPE)
            p.stderr.close()

            commit_hash = p.stdout.readlines()[0].strip()
            if not commit_hash:
                break

            tag = call_git_describe(abbrev, commit_hash)
            if not tag:
                break

            # Only look at tags without a dash, others are commits between tags
            if '-' not in tag and tag != my_tag:
                prev_tag_commit_hash = commit_hash
                prev_tag = tag
                break

            # Get the commit entry
            cmd = ['git', 'log', '--first-parent', '--pretty=%s', '-1', tag]
            p = Popen(cmd, stdout=PIPE, stderr=PIPE)
            p.stderr.close()
            lines = p.stdout.readlines()
            lines = [l.strip() for l in lines]
            commits.append(lines)

            skip += 1

        # Did we find it?
        if not prev_tag:
            return None

        # Get the commit timestamp
        cmd = ['git', 'show', '-s', '--pretty=%ci', prev_tag_commit_hash]
        p = Popen(cmd, stdout=PIPE, stderr=PIPE)
        p.stderr.close()
        when = p.stdout.readlines()[0].strip()

        # Build the changelog
        header = 'Version %s' % my_tag
        changelog = [header,
                     '=' * len(header),
                     'Released: %s' % when,
                     '']
        for commit in commits:
            changelog += [' * %s' % commit[0]]
            for line in commit[1:]:
                changelog += ['   %s' % line]
        return '\n'.join(changelog)
    except:
        return None


def read_release_version():
    try:
        f = open("RELEASE-VERSION", "r")

        try:
            version = f.readlines()[0]
            return version.strip()

        finally:
            f.close()

    except:
        return None


def write_release_version(version):
    f = open("RELEASE-VERSION", "w")
    f.write("%s\n" % version)
    f.close()


def write_changelog(version, changelog):
    f = open("changes/ChangeLog-%s.md" % version, "w")
    f.write('%s\n' % changelog)
    f.close()


def get_git_version(abbrev=4):
    # Read in the version that's currently in RELEASE-VERSION.
    release_version = read_release_version()

    # First try to get the current version using “git describe”.
    version = call_git_describe(abbrev)

    # If that doesn't work, fall back on the value that's in
    # RELEASE-VERSION.
    if version is None:
        version = release_version

    # If we still don't have anything, that's an error.
    if version is None:
        raise ValueError("Cannot find the version number!")

    # If the current version is different from what's in the
    # RELEASE-VERSION file, update the file to be current.
    if version != release_version:
        write_release_version(version)

    # Get the changelog
    changelog = get_git_changelog()
    if changelog:
        write_changelog(version, changelog)

    # Finally, return the current version.
    return version


if __name__ == "__main__":
    print get_git_version()
