## libevent ABI/API changes


This script is used to generate information about changes in libevent ABI/API
between various versions using [LVC tools](https://github.com/lvc). Such an
overview can help developers migrate from one version to another.

Here is the `abi_check.sh`, which is used to generate ABI/API timeline for
libevent.

You can limit the number of included libevent versions via a number given
as a parameter to the script. For example

```shell
$ ./abi_check.sh 3
```

generates overview for the last 3 versions and the current version.
If no parameter given, it will generate overview for the last 2 versions and
the current version by default.

But this script requires some tools that are available in the following docker image:

```
docker.pkg.github.com/azat/docker-images/lvc-debian
```

And the full command looks like:

```shell
  docker run --rm -it -v $PWD:/src:ro -w /src -v tmp/le-abi-check-root:/abi-root -e ABI_CHECK_ROOT=/abi-root docker.pkg.github.com/azat/docker-images/lvc-debian /src/extra/abi-check/abi_check.sh
```

'timeline/libevent/index.html' is the final result and can be viewed
[here](https://libevent.org/abi)
