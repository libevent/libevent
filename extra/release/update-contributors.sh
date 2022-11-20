#!/usr/bin/env bash

function path_in_repo()
{
    echo "$(git rev-parse --show-toplevel)/$*"
}
function main()
{
    local new_contributors
    new_contributors="$(mktemp libevent.XXXXXX)"
    trap "rm $new_contributors $new_contributors.filtered" EXIT

    git log "$(git describe --abbrev=0)..HEAD" --pretty='format:%cN%n%aN' > "$new_contributors"
    awk '/^ \* / { split($0, cols, " \\* "); print(cols[2]); }' "$(path_in_repo CONTRIBUTORS.md)" | {
        grep -F -x -v -f- "$new_contributors"
    } | {
        local grep_patterns=(
            -e GitHub
        )
        grep -F -x -v "${grep_patterns[@]}" 
    } | sort -u > "$new_contributors.filtered"
    awk '{printf(" * %s\n", $0)}' "$new_contributors.filtered" >> "$(path_in_repo CONTRIBUTORS.md)"
}
main "$@"
