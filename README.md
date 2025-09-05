# GitLab Multi group/user Project

The idea we are tring to implement here is to, one project multiple brunches, inidivisual user/group will work on inidivisual branches. 

Here, we will also separate the users in to multiple groups. The access permission will be based on under which group the user is in.

The project is devided into 4 groups and 5 brunchs.

The 4 groups are:
    + `fsladmin`
    + `darmstadt`
    + `hamburg`
    + `berlin`

The 5 brunches are:
    + `main`
    + `testing`
    + `darmstadt`
    + `hamburg`
    + `berlin`


The users from `darmstadt`, `hamburg`, and `berlin` group will work on there respected brunches. The `fsladmin` will marge `darmstadt`, `hamburg`, and `berlin` branches into the `testing` brunch.
After the testing is successful by `fsladmin`, then the final validated file will move to the `main` brunch. 


For now once in a week(Every Monday Morning) the testing will run manually.

## User Instruction for `darmstadt`, `hamburg`, and `berlin` 

Admin will assign user into his/her respected group.
One user can be in one group at a same time.
User has permission to wright into his/her own branch only.
User can see or read all the other brunches.


## Technical guideline for Users

### Step 1

Clone the git repository, with the command 

```bash
git clone GIT_REPOSITORY_LINK
```

Go to the git repository local directory

```bash
cd GIT_REPOSITORY
```

### Step 2

Check the brunch name and make sure you are on the correct branch.

```bash
git checkout BRANCH_NAME
```

BRANCH_NAME = darmstadt, hamburg, or berlin


To check any chaanges in the git branch.

```bash
git fetch origin            # check for updates
git status                  # see if behind or up to date
```


If you want to actually see those new commits before pulling:

```bash
git log --oneline origin/BRANCH_NAME 
```


 


### Step 3

After editing or working, to push/upload this file into the gitlab in your own brunch.

+ For all the files in that directory/folder.
```bash
git add .
```

+ For a specific file

```bash
git add FILE_NAME
```


After git add, you have to make a comment with a very short message about what you have done in this version. So that others can understand what changes you have added/done in the new version.
Keep the  commit messages meaningful, short and othes can understand.

```bash
git commit -m "CONNEMNT BY THE USER SUMMARY (<= 72 chars)"
```

### Step 4

After commit, you have to push it into the gitlab online server.

```bash
git push -u origin BRANCH_NAME
```

Now you can refresh the gitlab webpage and you will see the updated version with the commit.


## Technical guideline for Admin

### Admin restore 1 to Many Files into `TEST_BRANCH` from `BRANCH_NAME`





### Admin Full Merge into `TEST_BRANCH` from `BRANCH_NAME`


#### Step 1

Clone the git repository, with the command 

```bash
git clone GIT_REPOSITORY_LINK
```

Go to the git repository local directory

```bash
cd GIT_REPOSITORY
```


#### Step 2

At first get the latest testing branch


```bash
git fetch origin
git checkout TEST_BRANCH
git pull --ff-only origin TEST_BRANCH  

```

#### Step 3

Merge Group branches into `TEST_BRANCH` one by one.

```bash

# Merge BRANCH_NAME
git merge --no-ff origin/BRANCH_NAME -m "merge: integrate 'darmstadt' into testing"

```

To fix any conflicts if any → edit files, then then add and commit it into the `TEST_BRANCH`


```bash
git add -A
git commit

```

Now push the commit 

```bash
git push origin TEST_BRANCH
```

#### Step 4

If the testing is validated them, merge `TEST_BRANCH` into `main`.

Go to `main` branch atfirst

```bash

git checkout main
git pull --ff-only origin main
```

Now marge `TEST_BRANCH` into `main` brunch.

```bash

git merge --no-ff origin/TEST_BRANCH -m "release: promote testing into main"
git push origin main

```
