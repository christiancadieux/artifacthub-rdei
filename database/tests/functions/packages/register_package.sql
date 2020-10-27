-- Start transaction and plan tests
begin;
select plan(13);

-- Declare some variables
\set org1ID '00000000-0000-0000-0000-000000000001'
\set repo1ID '00000000-0000-0000-0000-000000000001'
\set user1ID '00000000-0000-0000-0000-000000000001'

-- Seed some data
insert into organization (organization_id, name, display_name, description, home_url)
values (:'org1ID', 'org1', 'Organization 1', 'Description 1', 'https://org1.com');
insert into "user" (user_id, alias, email) values (:'user1ID', 'user1', 'user1@email.com');
insert into repository (repository_id, name, display_name, url, repository_kind_id, organization_id)
values (:'repo1ID', 'repo1', 'Repo 1', 'https://repo1.com', 0, :'org1ID');

-- Register package
select register_package('
{
    "name": "package1",
    "logo_url": "logo_url",
    "logo_image_id": "00000000-0000-0000-0000-000000000001",
    "channels": [
        {
            "name": "stable",
            "version": "1.0.0"
        },
        {
            "name": "alpha",
            "version": "1.1.0"
        }
    ],
    "default_channel": "stable",
    "display_name": "Package 1",
    "description": "description",
    "keywords": ["kw1", "kw2"],
    "home_url": "home_url",
    "readme": "readme-version-1.0.0",
    "install": "install-version-1.0.0",
    "links": [
        {
            "name": "link1",
            "url": "https://link1"
        },
        {
            "name": "link2",
            "url": "https://link2"
        }
    ],
    "crds": [{
        "key": "value"
    }],
    "crds_examples": [{
        "key": "value"
    }],
    "data": {
        "key": "value"
    },
    "version": "1.0.0",
    "app_version": "12.1.0",
    "digest": "digest-package1-1.0.0",
    "deprecated": false,
    "license": "Apache-2.0",
    "signed": false,
    "content_url": "https://package.content.url",
    "is_operator": true,
    "capabilities": "basic install",
    "containers_images": [
        {
            "image": "quay.io/org/img:1.0.0"
        }
    ],
    "provider": "Org Inc",
    "values_schema": {
        "key": "value"
    },
    "changes": [
        "Added cool feature",
        "Fixed minor bug"
    ],
    "created_at": 1592299234,
    "maintainers": [
        {
            "name": "name1",
            "email": "email1"
        },
        {
            "name": "name2",
            "email": "email2"
        }
    ],
    "repository": {
        "repository_id": "00000000-0000-0000-0000-000000000001"
    }
}
');
select results_eq(
    $$
        select
            name,
            latest_version,
            logo_url,
            logo_image_id,
            is_operator,
            channels,
            default_channel,
            repository_id
        from package
        where name='package1'
    $$,
    $$
        values (
            'package1',
            '1.0.0',
            'logo_url',
            '00000000-0000-0000-0000-000000000001'::uuid,
            true,
            '[
                {
                    "name": "stable",
                    "version": "1.0.0"
                },
                {
                    "name": "alpha",
                    "version": "1.1.0"
                }
            ]'::jsonb,
            'stable',
            '00000000-0000-0000-0000-000000000001'::uuid
        )
    $$,
    'Package should exist'
);
select results_eq(
    $$
        select
            s.version,
            s.display_name,
            s.description,
            s.keywords,
            s.home_url,
            s.app_version,
            s.digest,
            s.readme,
            s.install,
            s.links,
            s.crds,
            s.crds_examples,
            s.capabilities,
            s.data,
            s.deprecated,
            s.license,
            s.signed,
            s.content_url,
            s.containers_images,
            s.provider,
            s.values_schema,
            s.changes,
            s.created_at
        from snapshot s
        join package p using (package_id)
        where name='package1'
        and version='1.0.0'
    $$,
    $$
        values (
            '1.0.0',
            'Package 1',
            'description',
            '{kw1,kw2}'::text[],
            'home_url',
            '12.1.0',
            'digest-package1-1.0.0',
            'readme-version-1.0.0',
            'install-version-1.0.0',
            '[{"name": "link1", "url": "https://link1"}, {"name": "link2", "url": "https://link2"}]'::jsonb,
            '[{"key": "value"}]'::jsonb,
            '[{"key": "value"}]'::jsonb,
            'basic install',
            '{"key": "value"}'::jsonb,
            false,
            'Apache-2.0',
            false,
            'https://package.content.url',
            '[{"image": "quay.io/org/img:1.0.0"}]'::jsonb,
            'Org Inc',
            '{"key": "value"}'::jsonb,
            '{
                "Added cool feature",
                "Fixed minor bug"
            }'::text[],
            '2020-06-16 11:20:34+02'::timestamptz
        )
    $$,
    'Snapshot should exist'
);
select results_eq(
    $$
        select name, email
        from maintainer m
        where maintainer_id in (
            select maintainer_id
            from package__maintainer pm
            join package p using (package_id)
            where p.name = 'package1'
        )
    $$,
    $$
        values
        ('name1', 'email1'),
        ('name2', 'email2')
    $$,
    'Maintainers should exist'
);
select is_empty(
    $$
        select *
        from event e
        join package p using (package_id)
        where p.name = 'package1'
    $$,
    'No new release event should exist for first version of package1'
);

-- Register a new version of the package previously registered
select register_package('
{
    "name": "package1",
    "logo_url": "logo_url updated",
    "logo_image_id": "00000000-0000-0000-0000-000000000001",
    "display_name": "Package 1 v2",
    "description": "description v2",
    "keywords": ["kw1", "kw2"],
    "home_url": "home_url",
    "readme": "readme-version-2.0.0",
    "install": "install-version-2.0.0",
    "version": "2.0.0",
    "app_version": "13.0.0",
    "digest": "digest-package1-2.0.0",
    "deprecated": true,
    "signed": true,
    "is_operator": false,
    "capabilities": "seamless upgrades",
    "containers_images": [
        {
            "image": "quay.io/org/img:2.0.0"
        }
    ],
    "provider": "Org Inc 2",
    "values_schema": null,
    "created_at": 1592299235,
    "maintainers": [
        {
            "name": "name1 updated",
            "email": "email1"
        }
    ],
    "repository": {
        "repository_id": "00000000-0000-0000-0000-000000000001"
    }
}
');
select results_eq(
    $$
        select logo_url, is_operator from package where name = 'package1'
    $$,
    $$
        values ('logo_url updated', false)
    $$,
    'Package logo url should have been updated'
);
select results_eq(
    $$
        select
            s.version,
            s.display_name,
            s.description,
            s.keywords,
            s.home_url,
            s.app_version,
            s.digest,
            s.readme,
            s.install,
            s.links,
            s.capabilities,
            s.deprecated,
            s.signed,
            s.containers_images,
            s.provider,
            s.values_schema,
            s.changes,
            s.created_at
        from snapshot s
        join package p using (package_id)
        where name='package1'
        and version='2.0.0'
    $$,
    $$
        values (
            '2.0.0',
            'Package 1 v2',
            'description v2',
            '{kw1,kw2}'::text[],
            'home_url',
            '13.0.0',
            'digest-package1-2.0.0',
            'readme-version-2.0.0',
            'install-version-2.0.0',
            null::jsonb,
            'seamless upgrades',
            true,
            true,
            '[{"image": "quay.io/org/img:2.0.0"}]'::jsonb,
            'Org Inc 2',
            null::jsonb,
            null::text[],
            '2020-06-16 11:20:35+02'::timestamptz
        )
    $$,
    'New snapshot should exist'
);
select results_eq(
    $$
        select name, email
        from maintainer m
        where maintainer_id in (
            select maintainer_id
            from package__maintainer pm
            join package p using (package_id)
            where p.name = 'package1'
        )
    $$,
    $$ values ('name1 updated', 'email1') $$,
    'Package maintainers should have been updated'
);
select is_empty(
    $$
        select *
        from maintainer m
        where maintainer_id not in (
            select maintainer_id from package__maintainer
        )
    $$,
    'Orphan maintainers were deleted'
);
select isnt_empty(
    $$
        select *
        from event e
        join package p using (package_id)
        where p.name = 'package1'
        and e.package_version = '2.0.0'
    $$,
    'New release event should exist for package1 version 2.0.0'
);

-- Register an old version of the package previously registered
select register_package('
{
    "name": "package1",
    "display_name": "Package 1",
    "description": "description",
    "logo_url": "logo_url",
    "home_url": "home_url",
    "logo_image_id": "00000000-0000-0000-0000-000000000001",
    "readme": "readme-version-0.0.9",
    "install": "install-version-0.0.9",
    "version": "0.0.9",
    "app_version": "11.0.0",
    "digest": "digest-package1-0.0.9",
    "deprecated": true,
    "signed": true,
    "is_operator": true,
    "capabilities": "basic install",
    "containers_images": [
        {
            "image": "quay.io/org/img:0.0.9"
        }
    ],
    "provider": "Org Inc",
    "created_at": 1592299233,
    "maintainers": [
        {
            "name": "name1",
            "email": "email1"
        },
        {
            "name": "name2",
            "email": "email2"
        }
    ],
    "repository": {
        "repository_id": "00000000-0000-0000-0000-000000000001"
    }
}
');
select results_eq(
    $$
        select logo_url, is_operator from package where name = 'package1'
    $$,
    $$
        values ('logo_url updated', false)
    $$,
    'Package logo url should not have been updated'
);
select results_eq(
    $$
        select
            s.version,
            s.display_name,
            s.description,
            s.keywords,
            s.home_url,
            s.app_version,
            s.digest,
            s.readme,
            s.install,
            s.links,
            s.capabilities,
            s.deprecated,
            s.signed,
            s.containers_images,
            s.provider,
            s.created_at
        from snapshot s
        join package p using (package_id)
        where name='package1'
        and version='0.0.9'
    $$,
    $$
        values (
            '0.0.9',
            'Package 1',
            'description',
            null::text[],
            'home_url',
            '11.0.0',
            'digest-package1-0.0.9',
            'readme-version-0.0.9',
            'install-version-0.0.9',
            null::jsonb,
            'basic install',
            true,
            true,
            '[{"image": "quay.io/org/img:0.0.9"}]'::jsonb,
            'Org Inc',
            '2020-06-16 11:20:33+02'::timestamptz
        )
    $$,
    'New snapshot should exist'
);
select results_eq(
    $$
        select name, email
        from maintainer m
        where maintainer_id in (
            select maintainer_id
            from package__maintainer pm
            join package p using (package_id)
            where p.name = 'package1'
        )
    $$,
    $$ values ('name1 updated', 'email1') $$,
    'Package maintainers should not have been updated'
);
select is_empty(
    $$
        select *
        from event e
        join package p using (package_id)
        where p.name = 'package1'
        and e.package_version = '0.0.9'
    $$,
    'No new release event should exist for package1 version 0.0.9'
);

-- Finish tests and rollback transaction
select * from finish();
rollback;
