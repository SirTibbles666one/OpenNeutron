use serde_json;
use tiny_http::{Request, Response};
use std::sync::Arc;
use std::io::Cursor;
use crate::core::{UserStorage, EmailStorage, User, Group};
use crate::api::request::read_json_body;
use crate::api::dto::{
    GroupDto, GroupsListResponse, CreateGroupRequest, GetGroupRequest,
    UpdateGroupRequest, DeleteGroupRequest, GroupEmailRequest,
    ErrorResponse, MessageResponse, json_header,
};

pub fn list_groups(
    _request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Unauthorized".into(), code: "unauthorized".into() }).unwrap();
            return Response::from_data(err).with_status_code(401).with_header(json_header());
        }
    };

    // Subject rules live in a sidecar (see core::subject_rules), so they are folded in
    // here rather than coming from the bincode `Group`.
    let subjects = crate::core::subject_rules::all(&user.username);
    let resp = GroupsListResponse {
        groups: user
            .groups
            .iter()
            .map(|g| {
                let mut dto = GroupDto::from(g);
                dto.filter_subjects = subjects.get(&g.uid).cloned().unwrap_or_default();
                dto
            })
            .collect(),
    };
    let body = serde_json::to_vec(&resp).unwrap();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

pub fn create_group(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Unauthorized".into(), code: "unauthorized".into() }).unwrap();
            return Response::from_data(err).with_status_code(401).with_header(json_header());
        }
    };

    let req: CreateGroupRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let group = Group::new(req.title, req.filter_addresses.unwrap_or_default());
    let dto = GroupDto::from(&group);
    user_storage.add_group(&user.username, group);

    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[API] Failed to persist after group create: {}", e);
    }

    let body = serde_json::to_vec(&dto).unwrap();
    Response::from_data(body).with_status_code(201).with_header(json_header())
}

pub fn get_group(
    request: &mut Request,
    user: Option<User>,
    _user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Unauthorized".into(), code: "unauthorized".into() }).unwrap();
            return Response::from_data(err).with_status_code(401).with_header(json_header());
        }
    };

    let req: GetGroupRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    match user.groups.iter().find(|g| g.uid == req.uid) {
        Some(group) => {
            let body = serde_json::to_vec(&GroupDto::from(group)).unwrap();
            Response::from_data(body).with_status_code(200).with_header(json_header())
        }
        None => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Group not found".into(), code: "group_not_found".into() }).unwrap();
            Response::from_data(err).with_status_code(404).with_header(json_header())
        }
    }
}

pub fn update_group(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Unauthorized".into(), code: "unauthorized".into() }).unwrap();
            return Response::from_data(err).with_status_code(401).with_header(json_header());
        }
    };

    let req: UpdateGroupRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let existing = match user.groups.iter().find(|g| g.uid == req.uid) {
        Some(g) => g.clone(),
        None => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Group not found".into(), code: "group_not_found".into() }).unwrap();
            return Response::from_data(err).with_status_code(404).with_header(json_header());
        }
    };

    let updated = Group {
        uid: existing.uid,
        title: req.title.unwrap_or(existing.title),
        email_uids: existing.email_uids,
        filter_addresses: req.filter_addresses
            .map(|addrs| addrs.into_iter().map(|a| a.to_lowercase()).collect())
            .unwrap_or(existing.filter_addresses),
    };

    user_storage.update_group(&user.username, updated.clone());

    // `None` means the caller is an older client that knows nothing about subjects — do
    // not treat that as "clear the rules this person configured".
    let subjects_now = match req.filter_subjects {
        Some(list) => {
            if let Err(e) = crate::core::subject_rules::set(&user.username, updated.uid, list) {
                log::warn!("[API] Could not save subject rules: {}", e);
            }
            crate::core::subject_rules::get(&user.username, updated.uid)
        }
        None => crate::core::subject_rules::get(&user.username, updated.uid),
    };

    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[API] Failed to persist after group update: {}", e);
    }

    let mut dto = GroupDto::from(&updated);
    dto.filter_subjects = subjects_now;
    let body = serde_json::to_vec(&dto).unwrap();
    Response::from_data(body).with_status_code(200).with_header(json_header())
}

pub fn delete_group(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Unauthorized".into(), code: "unauthorized".into() }).unwrap();
            return Response::from_data(err).with_status_code(401).with_header(json_header());
        }
    };

    let req: DeleteGroupRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    if !user_storage.delete_group(&user.username, req.uid) {
        let err = serde_json::to_vec(&ErrorResponse { error: "Group not found".into(), code: "group_not_found".into() }).unwrap();
        return Response::from_data(err).with_status_code(404).with_header(json_header());
    }

    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[API] Failed to persist after group delete: {}", e);
    }

    let msg = serde_json::to_vec(&MessageResponse { message: "Group deleted".into() }).unwrap();
    Response::from_data(msg).with_status_code(200).with_header(json_header())
}

pub fn add_email_to_group(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Unauthorized".into(), code: "unauthorized".into() }).unwrap();
            return Response::from_data(err).with_status_code(401).with_header(json_header());
        }
    };

    let req: GroupEmailRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    if !user.emailIds.contains(&req.email_uid) {
        let err = serde_json::to_vec(&ErrorResponse { error: "Email not found".into(), code: "email_not_found".into() }).unwrap();
        return Response::from_data(err).with_status_code(404).with_header(json_header());
    }

    if !user_storage.add_email_to_group(&user.username, req.group_uid, req.email_uid) {
        let err = serde_json::to_vec(&ErrorResponse { error: "Group not found".into(), code: "group_not_found".into() }).unwrap();
        return Response::from_data(err).with_status_code(404).with_header(json_header());
    }

    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[API] Failed to persist after add-email-to-group: {}", e);
    }

    let msg = serde_json::to_vec(&MessageResponse { message: "Email added to group".into() }).unwrap();
    Response::from_data(msg).with_status_code(200).with_header(json_header())
}

pub fn remove_email_from_group(
    request: &mut Request,
    user: Option<User>,
    user_storage: Arc<UserStorage>,
    _email_storage: Arc<EmailStorage>,
) -> Response<Cursor<Vec<u8>>> {
    let user = match user {
        Some(u) => u,
        None => {
            let err = serde_json::to_vec(&ErrorResponse { error: "Unauthorized".into(), code: "unauthorized".into() }).unwrap();
            return Response::from_data(err).with_status_code(401).with_header(json_header());
        }
    };

    let req: GroupEmailRequest = match read_json_body(request) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    if !user_storage.remove_email_from_group(&user.username, req.group_uid, req.email_uid) {
        let err = serde_json::to_vec(&ErrorResponse { error: "Group not found".into(), code: "group_not_found".into() }).unwrap();
        return Response::from_data(err).with_status_code(404).with_header(json_header());
    }

    if let Err(e) = user_storage.save_to_file() {
        log::warn!("[API] Failed to persist after remove-email-from-group: {}", e);
    }

    let msg = serde_json::to_vec(&MessageResponse { message: "Email removed from group".into() }).unwrap();
    Response::from_data(msg).with_status_code(200).with_header(json_header())
}
