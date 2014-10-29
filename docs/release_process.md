## Steps

1. Roll new version number
  1. Update `lib/modsec.rb`
  2. Update `debian/changelog`
  3. Update `CHANGELOG.md`
2. `git tag -a x.x.x HEAD`
3. `git checkout production`
4. `git merge master`
5. `git push --all`
6. `git push --tags`