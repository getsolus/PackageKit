/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2007 Richard Hughes <richard@hughsie.com>
 * Copyright (C) 2007 S.Çağlar Onur <caglar@pardus.org.tr>
 *
 * Licensed under the GNU General Public License Version 2
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <pk-backend.h>
#include <pk-backend-spawn.h>

static PkBackendSpawn *spawn;

static const gchar *eopkg_get_backend_filename (void);

static const gchar
*eopkg_get_backend_filename (void)
{
    if (g_file_test ("/usr/share/PackageKit/helpers/eopkg/eopkgBackend.bin", G_FILE_TEST_EXISTS)) {
        return "eopkgBackend.bin";
    } else {
        return "eopkgBackend.py";
    };
}

void
pk_backend_start_job (PkBackend *backend, PkBackendJob *job)
{
    if (pk_backend_spawn_is_busy (spawn)) {
        pk_backend_job_error_code (job,
                       PK_ERROR_ENUM_LOCK_REQUIRED,
                       "spawned backend requires lock");
        return;
    }
}

void
pk_backend_initialize (GKeyFile *conf, PkBackend *backend)
{
    g_debug ("backend: initialize");

    spawn = pk_backend_spawn_new (conf);
    pk_backend_spawn_set_name (spawn, "eopkg");
}

void
pk_backend_destroy (PkBackend *backend)
{
    g_debug ("backend: destroy");
    g_object_unref (spawn);
}

PkBitfield
pk_backend_get_groups (PkBackend *backend)
{
    return pk_bitfield_from_enums (
        PK_GROUP_ENUM_ACCESSORIES,
        PK_GROUP_ENUM_EDUCATION,
        PK_GROUP_ENUM_GAMES,
        PK_GROUP_ENUM_INTERNET,
        PK_GROUP_ENUM_OTHER,
        PK_GROUP_ENUM_PROGRAMMING,
        PK_GROUP_ENUM_MULTIMEDIA,
        PK_GROUP_ENUM_SYSTEM,
        PK_GROUP_ENUM_DESKTOP_GNOME,
        PK_GROUP_ENUM_DESKTOP_KDE,
        PK_GROUP_ENUM_DESKTOP_OTHER,
        PK_GROUP_ENUM_PUBLISHING,
        PK_GROUP_ENUM_SERVERS,
        PK_GROUP_ENUM_FONTS,
        PK_GROUP_ENUM_ADMIN_TOOLS,
        PK_GROUP_ENUM_LOCALIZATION,
        PK_GROUP_ENUM_VIRTUALIZATION,
        PK_GROUP_ENUM_SECURITY,
        PK_GROUP_ENUM_POWER_MANAGEMENT,
        PK_GROUP_ENUM_UNKNOWN,
        -1);
}

PkBitfield
pk_backend_get_filters (PkBackend *backend)
{
    return pk_bitfield_from_enums(
        PK_FILTER_ENUM_GUI,
        PK_FILTER_ENUM_INSTALLED,
        PK_FILTER_ENUM_NOT_INSTALLED,
        PK_FILTER_ENUM_NEWEST,
        -1);
}

gchar **
pk_backend_get_mime_types(PkBackend *backend)
{
    const gchar *mime_types[] = {
            "application/zip",
            NULL };
    return g_strdupv ((gchar **) mime_types);
}

void
pk_backend_cancel (PkBackend *backend, PkBackendJob *job)
{
    /* this feels bad... */
    pk_backend_spawn_kill (spawn);
}

void
pk_backend_download_packages (PkBackend *backend, PkBackendJob *job, gchar **package_ids, const gchar *directory)
{
    const gchar *backend_filename = NULL;
    gchar *package_ids_temp;

    /* send the complete list as stdin */
    package_ids_temp = pk_package_ids_to_string (package_ids);
    backend_filename = eopkg_get_backend_filename ();
    pk_backend_spawn_helper (spawn, job, backend_filename, "download-packages", directory, package_ids_temp, NULL);
    g_free (package_ids_temp);
}

void
pk_backend_get_categories (PkBackend *backend, PkBackendJob *job)
{
    const gchar *backend_filename = NULL;

    backend_filename = eopkg_get_backend_filename ();

    pk_backend_spawn_helper (spawn, job, backend_filename, "get-categories", NULL);
}

void
pk_backend_depends_on (PkBackend *backend, PkBackendJob *job, PkBitfield filters, gchar **package_ids, gboolean recursive)
{
    const gchar *backend_filename = NULL;
    gchar *filters_text;
    gchar *package_ids_temp;

    backend_filename = eopkg_get_backend_filename ();
    package_ids_temp = pk_package_ids_to_string (package_ids);
    filters_text = pk_filter_bitfield_to_string (filters);
    pk_backend_spawn_helper (spawn, job, backend_filename, "depends-on", filters_text, package_ids_temp, pk_backend_bool_to_string (recursive), NULL);
    g_free (filters_text);
    g_free (package_ids_temp);
}

void
pk_backend_get_details (PkBackend *backend, PkBackendJob *job, gchar **package_ids)
{
    const gchar *backend_filename = NULL;
    gchar *package_ids_temp;

    backend_filename = eopkg_get_backend_filename ();
    package_ids_temp = pk_package_ids_to_string (package_ids);
    pk_backend_spawn_helper (spawn, job, backend_filename, "get-details", package_ids_temp, NULL);
    g_free (package_ids_temp);
}

void
pk_backend_get_details_local (PkBackend *backend, PkBackendJob *job, gchar **files)
{
    const gchar *backend_filename = NULL;
    gchar *package_ids_temp;

    backend_filename = eopkg_get_backend_filename ();
    package_ids_temp = pk_package_ids_to_string (files);
    pk_backend_spawn_helper (spawn, job, backend_filename, "get-details-local", package_ids_temp, NULL);
    g_free (package_ids_temp);
}

void
pk_backend_get_distro_upgrades (PkBackend *backend, PkBackendJob *job)
{
        pk_backend_job_finished (job);
}

void
pk_backend_get_files (PkBackend *backend, PkBackendJob *job, gchar **package_ids)
{
    const gchar *backend_filename = NULL;
    gchar *package_ids_temp;

    backend_filename = eopkg_get_backend_filename ();
    package_ids_temp = pk_package_ids_to_string (package_ids);
    pk_backend_spawn_helper (spawn, job, backend_filename, "get-files", package_ids_temp, NULL);
    g_free (package_ids_temp);
}

void
pk_backend_required_by (PkBackend *backend, PkBackendJob *job, PkBitfield filters, gchar **package_ids, gboolean recursive)
{
    const gchar *backend_filename = NULL;
    gchar *filters_text;
    gchar *package_ids_temp;

    backend_filename = eopkg_get_backend_filename ();
    package_ids_temp = pk_package_ids_to_string (package_ids);
    filters_text = pk_filter_bitfield_to_string (filters);
    pk_backend_spawn_helper (spawn, job, backend_filename, "required-by", filters_text, package_ids_temp, pk_backend_bool_to_string (recursive), NULL);
    g_free (filters_text);
    g_free (package_ids_temp);
}

void
pk_backend_get_updates (PkBackend *backend, PkBackendJob *job, PkBitfield filters)
{
    const gchar *backend_filename = NULL;
    gchar *filters_text;
    backend_filename = eopkg_get_backend_filename ();
    filters_text = pk_filter_bitfield_to_string (filters);
    pk_backend_spawn_helper (spawn, job, backend_filename, "get-updates", filters_text, NULL);
    g_free (filters_text);
}

void
pk_backend_get_update_detail (PkBackend *backend, PkBackendJob *job, gchar **package_ids)
{
    const gchar *backend_filename = NULL;
    gchar *package_ids_temp;
    backend_filename = eopkg_get_backend_filename ();
    package_ids_temp = pk_package_ids_to_string (package_ids);
    pk_backend_spawn_helper (spawn, job, backend_filename, "get-update-detail", package_ids_temp, NULL);
    g_free (package_ids_temp);
}

void
pk_backend_install_packages (PkBackend *backend, PkBackendJob *job, PkBitfield transaction_flags, gchar **package_ids)
{
    const gchar *backend_filename = NULL;
    gchar *package_ids_temp;
    gchar *transaction_flags_temp;

    /* check network state */
    if (!pk_backend_is_online (backend)) {
        pk_backend_job_error_code (job, PK_ERROR_ENUM_NO_NETWORK, "Cannot install when offline");
        pk_backend_job_finished (job);
        return;
    }

    /* send the complete list as stdin */
    package_ids_temp = pk_package_ids_to_string (package_ids);
    transaction_flags_temp = pk_transaction_flag_bitfield_to_string (transaction_flags);

    backend_filename = eopkg_get_backend_filename ();

    pk_backend_spawn_helper (spawn, job, backend_filename, "install-packages", transaction_flags_temp, package_ids_temp, NULL);
    g_free (package_ids_temp);
    g_free (transaction_flags_temp);
}

void
pk_backend_install_files (PkBackend *backend, PkBackendJob *job, PkBitfield transaction_flags, gchar **full_paths)
{
    const gchar *backend_filename = NULL;
    gchar *package_ids_temp;
    gchar *transaction_flags_temp;

    /* send the complete list as stdin */
    package_ids_temp = g_strjoinv (PK_BACKEND_SPAWN_FILENAME_DELIM, full_paths);
    transaction_flags_temp = pk_transaction_flag_bitfield_to_string (transaction_flags);
    backend_filename = eopkg_get_backend_filename ();

    pk_backend_spawn_helper (spawn, job, backend_filename, "install-files", transaction_flags_temp, package_ids_temp, NULL);
    g_free (package_ids_temp);
    g_free (transaction_flags_temp);
}

void
pk_backend_refresh_cache (PkBackend *backend, PkBackendJob *job, gboolean force)
{
    const gchar *backend_filename = NULL;

    /* check network state */
    if (!pk_backend_is_online (backend)) {
        pk_backend_job_error_code (job, PK_ERROR_ENUM_NO_NETWORK, "Cannot refresh cache whilst offline");
        pk_backend_job_finished (job);
        return;
    }

    backend_filename = eopkg_get_backend_filename ();

    pk_backend_spawn_helper (spawn, job, backend_filename, "refresh-cache", pk_backend_bool_to_string (force), NULL);
}

void
pk_backend_remove_packages (PkBackend *backend, PkBackendJob *job,
                PkBitfield transaction_flags,
                gchar **package_ids,
                gboolean allow_deps,
                gboolean autoremove)
{
    const gchar *backend_filename = NULL;
    gchar *package_ids_temp;
    gchar *transaction_flags_temp;

    /* send the complete list as stdin */
    package_ids_temp = pk_package_ids_to_string (package_ids);
    transaction_flags_temp = pk_transaction_flag_bitfield_to_string (transaction_flags);

    backend_filename = eopkg_get_backend_filename ();

    pk_backend_spawn_helper (spawn,
        job, backend_filename,
        "remove-packages",
        transaction_flags_temp,
        package_ids_temp,
        pk_backend_bool_to_string (allow_deps),
        pk_backend_bool_to_string (autoremove),
        NULL);

    g_free (transaction_flags_temp);
    g_free (package_ids_temp);
}

void
pk_backend_repo_enable (PkBackend *backend, PkBackendJob *job, const gchar *rid, gboolean enabled)
{
    const gchar *backend_filename = NULL;

    backend_filename = eopkg_get_backend_filename ();

    pk_backend_spawn_helper (spawn, job, backend_filename, "repo-enable", rid, pk_backend_bool_to_string (enabled), NULL);
}

void
pk_backend_search_details (PkBackend *backend, PkBackendJob *job, PkBitfield filters, gchar **values)
{
    const gchar *backend_filename = NULL;
    gchar *filters_text;
    gchar *search;
    backend_filename = eopkg_get_backend_filename ();
    filters_text = pk_filter_bitfield_to_string (filters);
    search = g_strjoinv ("&", values);
    pk_backend_spawn_helper (spawn, job, backend_filename, "search-details", filters_text, search, NULL);
    g_free (search);
    g_free (filters_text);
}

void
pk_backend_search_files (PkBackend *backend, PkBackendJob *job, PkBitfield filters, gchar **values)
{
    const gchar *backend_filename = NULL;
    gchar *filters_text;
    gchar *search;
    backend_filename = eopkg_get_backend_filename ();
    filters_text = pk_filter_bitfield_to_string (filters);
    search = g_strjoinv ("&", values);
    pk_backend_spawn_helper (spawn, job, backend_filename, "search-file", filters_text, search, NULL);
    g_free (search);
    g_free (filters_text);
}

void
pk_backend_search_groups (PkBackend *backend, PkBackendJob *job, PkBitfield filters, gchar **values)
{
    const gchar *backend_filename = NULL;
    gchar *filters_text;
    gchar *search;
    backend_filename = eopkg_get_backend_filename ();
    filters_text = pk_filter_bitfield_to_string (filters);
    search = g_strjoinv ("&", values);
    pk_backend_spawn_helper (spawn, job, backend_filename, "search-group", filters_text, search, NULL);
    g_free (search);
    g_free (filters_text);
}

void
pk_backend_search_names (PkBackend *backend, PkBackendJob *job, PkBitfield filters, gchar **values)
{
    const gchar *backend_filename = NULL;
    gchar *filters_text;
    gchar *search;
    backend_filename = eopkg_get_backend_filename ();
    filters_text = pk_filter_bitfield_to_string (filters);
    search = g_strjoinv ("&", values);
    pk_backend_spawn_helper (spawn, job, backend_filename, "search-name", filters_text, search, NULL);
    g_free (search);
    g_free (filters_text);
}

void
pk_backend_update_packages (PkBackend *backend, PkBackendJob *job, PkBitfield transaction_flags, gchar **package_ids)
{
    const gchar *backend_filename = NULL;
    gchar *package_ids_temp;
    gchar *transaction_flags_temp;
    /* Disable network check for now to allow for offline updates */
    /* TODO: Can we check transaction_flags or something here for that case? */
    /*if (!pk_backend_is_online (backend)) {
        pk_backend_job_error_code (job, PK_ERROR_ENUM_NO_NETWORK, "Cannot install when offline");
        pk_backend_job_finished (job);
        return;
    }*/

    /* send the complete list as stdin */
    package_ids_temp = pk_package_ids_to_string (package_ids);
    transaction_flags_temp = pk_transaction_flag_bitfield_to_string (transaction_flags);
    backend_filename = eopkg_get_backend_filename ();

    pk_backend_spawn_helper (spawn, job, backend_filename, "update-packages", transaction_flags_temp, package_ids_temp, NULL);
    g_free (package_ids_temp);
    g_free (transaction_flags_temp);
}

void
pk_backend_get_packages (PkBackend *backend, PkBackendJob *job, PkBitfield filters)
{
    const gchar *backend_filename = NULL;
    gchar *filters_text;

    backend_filename = eopkg_get_backend_filename ();
    filters_text = pk_filter_bitfield_to_string (filters);
    pk_backend_spawn_helper (spawn, job, backend_filename, "get-packages", filters_text, NULL);
    g_free (filters_text);
}

void
pk_backend_resolve (PkBackend *backend, PkBackendJob *job, PkBitfield filters, gchar **package_ids)
{
    const gchar *backend_filename = NULL;
    gchar *filters_text;
    gchar *package_ids_temp;
    backend_filename = eopkg_get_backend_filename ();
    filters_text = pk_filter_bitfield_to_string (filters);
    package_ids_temp = pk_package_ids_to_string (package_ids);
    pk_backend_spawn_helper (spawn, job, backend_filename, "resolve", filters_text, package_ids_temp, NULL);
    g_free (filters_text);
    g_free (package_ids_temp);
}

void
pk_backend_get_repo_list (PkBackend *backend, PkBackendJob *job, PkBitfield filters)
{
    const gchar *backend_filename = NULL;
    gchar *filters_text;
    backend_filename = eopkg_get_backend_filename ();
    filters_text = pk_filter_bitfield_to_string (filters);
    pk_backend_spawn_helper (spawn, job, backend_filename, "get-repo-list", filters_text, NULL);
    g_free (filters_text);
}

void
pk_backend_repo_set_data (PkBackend *backend, PkBackendJob *job, const gchar *rid, const gchar *parameter, const gchar *value)
{
    const gchar *backend_filename = NULL;

    backend_filename = eopkg_get_backend_filename ();

    pk_backend_spawn_helper (spawn, job, backend_filename, "repo-set-data", rid, parameter, value, NULL);
}

void
pk_backend_repair_system (PkBackend *backend, PkBackendJob *job, PkBitfield transaction_flags)
{
    const gchar *backend_filename = NULL;
    gchar *transaction_flags_temp;

    backend_filename = eopkg_get_backend_filename ();
    transaction_flags_temp = pk_transaction_flag_bitfield_to_string (transaction_flags);

    pk_backend_spawn_helper (spawn, job, backend_filename, "repair-system", transaction_flags_temp, NULL);
    g_free (transaction_flags_temp);
}

gboolean
pk_backend_supports_parallelization (PkBackend *backend)
{
    return FALSE;
}

const gchar *
pk_backend_get_description (PkBackend *backend)
{
    return "Eopkg - Solus Package Manager";
}

const gchar *
pk_backend_get_author (PkBackend *backend)
{
    return "S.Çağlar Onur <caglar@pardus.org.tr>\nIkey Doherty <ikey@solusos.com>\nBerk Çakar <berk2238@hotmail.com>";
}
