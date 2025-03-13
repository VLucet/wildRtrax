#' Internal functions
#'
#' WildTrax authentication
#'
#' @description Get Auth0 token and assign information to the hidden environment
#'
#' @keywords internal
#'
#' @import httr2

.wt_auth <- function() {

  # ABMI Auth0 client ID
  cid <- rawToChar(
    as.raw(c(0x45, 0x67, 0x32, 0x4d, 0x50, 0x56, 0x74, 0x71, 0x6b,
             0x66, 0x33, 0x53, 0x75, 0x4b, 0x53, 0x35, 0x75, 0x58, 0x7a, 0x50,
             0x39, 0x37, 0x6e, 0x78, 0x55, 0x31, 0x33, 0x5a, 0x32, 0x4b, 0x31,
             0x69)))

  # Initialize request to Auth0
  req <-  httr2::request("https://abmi.auth0.com/")

  if (Sys.getenv("WT_USERNAME") == "" || Sys.getenv("WT_PASSWORD") == "") {
    stop(
      "Environment variables are not set:\n",
      " - WT_USERNAME: ", ifelse(Sys.getenv("WT_USERNAME") == "", "MISSING", "SET"), "\n",
      " - WT_PASSWORD: ", ifelse(Sys.getenv("WT_PASSWORD") == "", "MISSING", "SET"), "\n",
      "Please set these variables using Sys.setenv() or add them to your .Renviron file."
    )
  }

  r <- req |>
    httr2::req_url_path("oauth/token") |>
    httr2::req_body_form(
      audience = "http://www.wildtrax.ca",
      grant_type = "password",
      client_id = cid,
      username = Sys.getenv('WT_USERNAME'),
      password = Sys.getenv('WT_PASSWORD')) |>
    httr2::req_perform()

  # Check for authentication errors
  if (httr2::resp_is_error(r)) {
    stop(sprintf(
      "Authentication failed [%s]\n%s",
      httr2::resp_status(r),
      httr2::resp_body_json(r)$error_description
    ),
    call. = FALSE)
  }

  # Parse the JSON response
  x <- httr2::resp_body_json(r)

  # Calculate token expiry time
  t0 <- Sys.time()
  x$expiry_time <- t0 + x$expires_in

  # Check if the authentication environment exists
  if (!exists("._wt_auth_env_")) {
    stop("Cannot find the correct environment.", call. = FALSE)
  }

  # Send the token information to the ._wt_auth_env_ environment
  list2env(x, envir = ._wt_auth_env_)

  message("Authentication into WildTrax successful.")

  invisible(NULL)

}

#' Internal function to check if Auth0 token has expired
#'
#' @description Check if the Auth0 token has expired
#'
#' @keywords internal
#'

.wt_auth_expired <- function () {

  if (!exists("._wt_auth_env_"))
    stop("Cannot find the correct environment.", call. = TRUE)

  if (is.null(._wt_auth_env_$expiry_time))
    return(TRUE)

  ._wt_auth_env_$expiry_time <= Sys.time()
}

#' Generate user agent
#'
#' @description Generic function to to encapsulate user agents
#'
#' @keywords internal
#'

.gen_ua <- function() {
  user_agent <- getOption("HTTPUserAgent")
  if (is.null(user_agent)) {
    user_agent <- sprintf(
      "R/%s; R (%s)",
      getRversion(),
      paste(getRversion(), R.version$platform, R.version$arch, R.version$os)
    )
  }
  user_agent <- paste0("wildrtrax ", as.character(packageVersion("wildrtrax")), "; ", user_agent)
  return(user_agent)
}

#' Switch locale to another language
#'
#' @description Global function to allow a user to request data in another language. Currently English = en or French = fr.
#'
#' @keywords internal
#'

.language <- function(language = c("en", "fr")) {
  language <- match.arg(language) # Ensure valid language selection
  return(language)
}


#' An internal function to handle generic POST requests to WildTrax API
#'
#' @description Generic function to handle certain POST requests
#'
#' @param path The path to the API
#' @param ... Argument to pass along into POST query
#'
#' @keywords internal
#'
#' @import httr2

.wt_api_pr <- function(path, ...) {

  # Check if authentication has expired:
  if (.wt_auth_expired()) {stop("Please authenticate with wt_auth().", call. = FALSE)}

  ## User agent
  u <- .gen_ua()

  # Convert ... into a list
  query_params <- list(...)

  # Check if query_params is a list; if not, ensure it is treated as a list
  if (length(query_params) == 1 && is.character(query_params[[1]])) {
    # If there's only one element and it's a character, treat it as a named query
    query_params <- as.list(query_params)
  }

  r <- request("https://www-api.wildtrax.ca") |>
    req_url_path_append(path) |>
    req_url_query(!!!query_params) |>  # Unpack the list of query parameters
    req_headers(Authorization = paste("Bearer", ._wt_auth_env_$access_token)) |>
    req_user_agent(u) |>
    req_method("POST") |>
    req_timeout(1000000) |> # Blow this up
    req_perform()

  # Handle errors
  if (resp_status(r) >= 400) {
    stop(sprintf(
      "Authentication failed [%s]\n%s",
      resp_status(r),
      message),
      call. = FALSE)
  } else {
    return(r)
  }

}

#' An internal function to handle generic GET requests to WildTrax API
#'
#' @description Generic function to handle certain GET requests
#'
#' @param path The path to the API
#' @param ... Argument to pass along into GET query
#'
#' @keywords internal
#'
#' @import httr2

.wt_api_gr <- function(path, ...) {

  # Check if authentication has expired:
  if (.wt_auth_expired()) {stop("Please authenticate with wt_auth().", call. = FALSE)}

  ## User agent
  u <- .gen_ua()

  # Validate language input
  #accept_language <- .language(language)

  # Convert ... into a list
  query_params <- list(...)

  # Check if query_params is a list; if not, ensure it is treated as a list
  if (length(query_params) == 1 && is.character(query_params[[1]])) {
    # If there's only one element and it's a character, treat it as a named query
    query_params <- as.list(query_params)
  }

  r <- request("https://www-api.wildtrax.ca") |>
    req_url_path_append(path) |>
    req_url_query(!!!query_params) |>  # Unpack the list of query parameters
    #req_url_path_append(`Accept-Language` = accept_language) |>
    req_headers(Authorization = paste("Bearer", ._wt_auth_env_$access_token)) |>
    req_user_agent(u) |>
    req_method("GET") |>
    req_perform()

  # Handle errors
  if (resp_status(r) >= 400) {
    stop(sprintf(
      "Authentication failed [%s]\n%s",
      resp_status(r),
      message),
      call. = FALSE)
  } else {
    return(r)
  }

}

#' Internal function for QPAD offsets
#'
#' QPAD offsets, wrapped by the `wt_qpad_offsets` function.
#'
#' @description Functions to format reports for qpad offset calculation.
#'
#' @param data Dataframe output from the `wt_make_wide` function.
#' @param tz Character; whether or not the data is in local or UTC time ("local", or "utc"). Defaults to "local".
#' @param check_xy Logical; check whether coordinates are within the range that QPAD offsets are valid for.
#'
#' @keywords internal
#'
#' @import QPAD dplyr httr2
#' @importFrom terra extract rast vect project
#'

.make_x <- function(data, tz="local", check_xy=TRUE) {

  # Download message
  message("Downloading geospatial assets. This may take a moment.")

  # Function to download and read a raster file using httr2
  download_and_read_raster <- function(url, filename) {
    req <- request(url) |>
      req_perform()  # Perform the request

    # Save the response content to a file
    writeBin(req$body, filename)

    return(terra::rast(filename))  # Read the raster file
  }

  # Download and read TIFF files
  .rlcc <- download_and_read_raster("https://raw.githubusercontent.com/ABbiodiversity/wildRtrax-assets/main/lcc.tif", "lcc.tif")
  .rtree <- download_and_read_raster("https://raw.githubusercontent.com/ABbiodiversity/wildRtrax-assets/main/tree.tif", "tree.tif")
  .rd1 <- download_and_read_raster("https://raw.githubusercontent.com/ABbiodiversity/wildRtrax-assets/main/seedgrow.tif", "seedgrow.tif")
  .rtz <- download_and_read_raster("https://raw.githubusercontent.com/ABbiodiversity/wildRtrax-assets/main/utcoffset.tif", "utcoffset.tif")

  crs <- terra::crs(.rtree)

  #get vars
  date <- substr(data$recording_date_time, 1, 10)
  time <- substr(data$recording_date_time, 12, 19)
  lon <- as.numeric(data$longitude)
  lat <- as.numeric(data$latitude)
  dur <- as.numeric(data$task_duration)
  dis <- Inf

  #parse date+time into POSIXlt
  if(tz=="local"){
    dtm <- strptime(paste0(date, " ", time, ":00"),
                    format="%Y-%m-%d %H:%M:%S", tz="America/Edmonton")
  }
  if(tz=="utc"){
    dtm <- strptime(paste0(date, " ", time, ":00"),
                    format="%Y-%m-%d %H:%M:%S", tz="GMT")
  }
  day <- as.integer(dtm$yday)
  hour <- as.numeric(round(dtm$hour + dtm$min/60, 2))

  #checks
  checkfun <- function(x, name="", range=c(-Inf, Inf)) {
    if (any(x[!is.na(x)] < range[1] | x[!is.na(x)] > range[2])) {
      stop(sprintf("Parameter %s is out of range [%.0f, %.0f]", name, range[1], range[2]))
    }
    invisible(NULL)
  }

  #Coordinates
  if (check_xy) {
    checkfun(lon, "lon", c(-164, -52))
    checkfun(lat, "lat", c(39, 69))
  }

  if (any(is.infinite(lon)))
    stop("Parameter lon must be finite")
  if (any(is.infinite(lat)))
    stop("Parameter lat must be finite")

  #handling missing values
  ok_xy <- !is.na(lon) & !is.na(lat)
  #Other fields
  checkfun(day, "day", c(0, 365))
  checkfun(hour, "hour", c(0, 24))
  checkfun(dur, "dur", c(0, Inf))

  #intersect here
  xydf <- data.frame(x=lon, y=lat)
  xydf$x[is.na(xydf$x)] <- mean(xydf$x, na.rm=TRUE)
  xydf$y[is.na(xydf$y)] <- mean(xydf$y, na.rm=TRUE)
  xy <- vect(xydf, geom=c("x", "y"), crs="+proj=longlat +datum=WGS84 +ellps=WGS84 +towgs84=0,0,0")
  xy <- project(xy, crs)

  #LCC4 and LCC2
  vlcc <- terra::extract(.rlcc, xy)$lcc
  lcclevs <- c("0"="", "1"="Conif", "2"="Conif", "3"="", "4"="",
               "5"="DecidMixed", "6"="DecidMixed", "7"="", "8"="Open", "9"="",
               "10"="Open", "11"="Open", "12"="Open", "13"="Open", "14"="Wet",
               "15"="Open", "16"="Open", "17"="Open", "18"="", "19"="")
  lcc4 <- factor(lcclevs[vlcc+1], c("DecidMixed", "Conif", "Open", "Wet"))
  lcc2 <- lcc4
  levels(lcc2) <- c("Forest", "Forest", "OpenWet", "OpenWet")

  #TREE
  vtree <- terra::extract(.rtree, xy)$tree
  TREE <- vtree / 100
  TREE[TREE < 0 | TREE > 1] <- 0

  #raster::extract seedgrow value (this is rounded)
  d1 <- terra::extract(.rd1, xy)$seedgrow

  #UTC offset + 7 makes Alberta 0 (MDT offset) for local times
  if(tz=="local"){
    ltz <- terra::extract(.rtz, xy)$utcoffset + 7
  }
  if(tz=="utc"){
    ltz <- 0
  }

  message("Removing geospatial assets from local")

  # Remove once downloaded and read
  file.remove(list.files(pattern = "*.tif$"))

  #sunrise time adjusted by offset
  ok_dt <- !is.na(dtm)
  dtm[is.na(dtm)] <- mean(dtm, na.rm=TRUE)
  if(tz=="local"){
    sr <- suntools::sunriset(cbind("X"=xydf$x, "Y"=xydf$y),
                             as.POSIXct(dtm, tz="America/Edmonton"),
                             direction="sunrise", POSIXct.out=FALSE) * 24
  }
  if(tz=="utc"){
    sr <- suntools::sunriset(cbind("X"=xydf$x, "Y"=xydf$y),
                             as.POSIXct(dtm, tz="GMT"),
                             direction="sunrise", POSIXct.out=FALSE) * 24
  }
  TSSR <- round(unname((hour - sr + ltz) / 24), 4)

  #days since local spring
  DSLS <- (day - d1) / 365

  #transform the rest
  JDAY <- round(day / 365, 4) # 0-365
  TREE <- round(vtree / 100, 4)
  MAXDIS <- round(dis / 100, 4)
  MAXDUR <- round(dur, 4)

  out <- data.frame(
    TSSR=TSSR,
    JDAY=JDAY,
    DSLS=DSLS,
    LCC2=lcc2,
    LCC4=lcc4,
    TREE=TREE,
    MAXDUR=MAXDUR,
    MAXDIS=MAXDIS)
  out$TSSR[!ok_xy | !ok_dt] <- NA
  out$DSLS[!ok_xy] <- NA
  out$LCC2[!ok_xy] <- NA
  out$LCC4[!ok_xy] <- NA
  out$TREE[!ok_xy] <- NA

  return(out)

}

#' QPAD offsets, wrapped by the `wt_qpad_offsets` function.
#'
#' @description Functions to get the offsets.
#'
#' @param spp species for offset calculation.
#' @param x Dataframe out from the `.make_x` function.
#'
#' @keywords internal
#'
#' @import QPAD dplyr

.make_off <- function(spp, x){

  if (length(spp) > 1L)
    stop("spp argument must be length 1. Use a loop or map for multiple species.")
  spp <- as.character(spp)

  #checks
  if (!(spp %in% getBAMspecieslist()))
    stop(sprintf("Species %s has no QPAD estimate available", spp))

  #constant for NA cases
  cf0 <- exp(unlist(coefBAMspecies(spp, 0, 0)))

  #best model
  mi <- bestmodelBAMspecies(spp, type="BIC")
  cfi <- coefBAMspecies(spp, mi$sra, mi$edr)

  TSSR <- x$TSSR
  DSLS <- x$DSLS
  JDAY <- x$JDAY
  lcc2 <- x$LCC2
  lcc4 <- x$LCC4
  TREE <- x$TREE
  MAXDUR <- x$MAXDUR
  MAXDIS <- x$MAXDIS
  n <- nrow(x)

  #Design matrices for singing rates (`Xp`) and for EDR (`Xq`)
  Xp <- cbind(
    "(Intercept)"=1,
    "TSSR"=TSSR,
    "JDAY"=JDAY,
    "TSSR2"=TSSR^2,
    "JDAY2"=JDAY^2,
    "DSLS"=DSLS,
    "DSLS2"=DSLS^2)

  Xq <- cbind("(Intercept)"=1,
              "TREE"=TREE,
              "LCC2OpenWet"=ifelse(lcc4 %in% c("Open", "Wet"), 1, 0),
              "LCC4Conif"=ifelse(lcc4=="Conif", 1, 0),
              "LCC4Open"=ifelse(lcc4=="Open", 1, 0),
              "LCC4Wet"=ifelse(lcc4=="Wet", 1, 0))

  p <- rep(NA, n)
  A <- q <- p

  #design matrices matching the coefs
  Xp2 <- Xp[,names(cfi$sra),drop=FALSE]
  OKp <- rowSums(is.na(Xp2)) == 0
  Xq2 <- Xq[,names(cfi$edr),drop=FALSE]
  OKq <- rowSums(is.na(Xq2)) == 0

  #calculate p, q, and A based on constant phi and tau for the respective NAs
  p[!OKp] <- sra_fun(MAXDUR[!OKp], cf0[1])
  unlim <- ifelse(MAXDIS[!OKq] == Inf, TRUE, FALSE)
  A[!OKq] <- ifelse(unlim, pi * cf0[2]^2, pi * MAXDIS[!OKq]^2)
  q[!OKq] <- ifelse(unlim, 1, edr_fun(MAXDIS[!OKq], cf0[2]))

  #calculate time/lcc varying phi and tau for non-NA cases
  phi1 <- exp(drop(Xp2[OKp,,drop=FALSE] %*% cfi$sra))
  tau1 <- exp(drop(Xq2[OKq,,drop=FALSE] %*% cfi$edr))
  p[OKp] <- sra_fun(MAXDUR[OKp], phi1)
  unlim <- ifelse(MAXDIS[OKq] == Inf, TRUE, FALSE)
  A[OKq] <- ifelse(unlim, pi * tau1^2, pi * MAXDIS[OKq]^2)
  q[OKq] <- ifelse(unlim, 1, edr_fun(MAXDIS[OKq], tau1))

  #log(0) is not a good thing, apply constant instead
  ii <- which(p == 0)
  p[ii] <- sra_fun(MAXDUR[ii], cf0[1])

  #package output
  data.frame(
    p=p,
    q=q,
    A=A,
    correction=p*A*q,
    offset=log(p) + log(A) + log(q))

}

#' Column assignments
#'
#' @description Assign correct column types for reports
#'
#' @keywords internal
#'

.wt_col_types <- list(
  abundance = readr::col_character(),
  age_class = readr::col_character(),
  aru_task_status = readr::col_character(),
  behaviours = readr::col_character(),
  bounding_box_number = readr::col_character(),
  category = readr::col_character(),
  clip_channel_used = readr::col_character(),
  classifier_confidence = readr::col_double(),
  classifier_version = readr::col_character(),
  coat_attributes = readr::col_character(),
  coat_colours = readr::col_character(),
  date_deployed = readr::col_date(),
  date_retrieved = readr::col_date(),
  detection_time = readr::col_double(),
  disabled_for_autotag = readr::col_logical(),
  elevation = readr::col_double(),
  equipment = readr::col_character(),
  equipment_make = readr::col_character(),
  equipment_model = readr::col_character(),
  equipment_serial = readr::col_character(),
  has_collar = readr::col_logical(),
  has_eartag = readr::col_logical(),
  health_diseases = readr::col_character(),
  ihf = readr::col_character(),
  image_comments = readr::col_character(),
  image_date_time = readr::col_datetime(),
  image_exif_sequence = readr::col_character(),
  image_exif_temperature = readr::col_double(),
  image_fire = readr::col_logical(),
  image_fov = readr::col_character(),
  image_id = readr::col_double(),
  image_in_wildtrax = readr::col_logical(),
  image_is_blurred = readr::col_logical(),
  image_malfunction = readr::col_logical(),
  image_nice = readr::col_logical(),
  image_snow = readr::col_logical(),
  image_snow_depth_m = readr::col_double(),
  image_water_depth_m = readr::col_double(),
  image_trigger_mode = readr::col_character(),
  image_set_count_motion = readr::col_integer(),
  image_set_count_timelapse = readr::col_integer(),
  image_set_count_total = readr::col_integer(),
  image_set_end_date_time = readr::col_datetime(),
  image_set_id = readr::col_character(),
  image_set_start_date_time = readr::col_datetime(),
  image_set_status = readr::col_character(),
  image_set_url = readr::col_character(),
  image_url = readr::col_character(),
  individual_count = readr::col_character(),
  individual_order = readr::col_double(),
  is_enabled_project_species = readr::col_logical(),
  is_species_allowed_in_project = readr::col_logical(),
  latitude = readr::col_double(),
  location = readr::col_character(),
  location_buffer_m = readr::col_double(),
  location_comments = readr::col_character(),
  location_id = readr::col_double(),
  location_visibility = readr::col_character(),
  longitude = readr::col_double(),
  min_tag_freq = readr::col_double(),
  max_tag_freq = readr::col_double(),
  needs_review = readr::col_logical(),
  observer = readr::col_character(),
  observer_id = readr::col_double(),
  organization = readr::col_character(),
  project = readr::col_character(),
  project_description = readr::col_character(),
  project_id = readr::col_double(),
  project_results = readr::col_character(),
  project_status = readr::col_character(),
  recording_date_time = readr::col_datetime(),
  recording_id = readr::col_double(),
  recording_length = readr::col_double(),
  rms_peak_dbfs = readr::col_double(),
  source_file_name = readr::col_character(),
  species_class = readr::col_character(),
  species_code = readr::col_character(),
  species_common_name = readr::col_character(),
  species_individual_comments = readr::col_character(),
  species_scientific_name = readr::col_character(),
  start_s = readr::col_double(),
  end_s = readr::col_double(),
  tag_comments = readr::col_character(),
  tag_duration = readr::col_double(),
  tag_id = readr::col_double(),
  tag_is_verified = readr::col_logical(),
  tag_needs_review = readr::col_logical(),
  tag_rating = readr::col_character(),
  tagged_in_wildtrax = readr::col_logical(),
  task_comments = readr::col_character(),
  task_duration = readr::col_double(),
  task_id = readr::col_double(),
  task_method = readr::col_character(),
  task_url = readr::col_character(),
  task_status = readr::col_character(),
  version = readr::col_character(),
  vocalization = readr::col_character(),
  width = readr::col_double(),
  x_loc = readr::col_double(),
  y_loc = readr::col_double(),
  height = readr::col_double()
)

#' Internal evaluation function for acoustic classifiers
#'
#' @description Internal function to calculate precision, recall, and F-score for a given score threshold.
#'
#' @param data Output from the `wt_download_report()` function when you request the `main` and `birdnet` reports
#' @param threshold A single numeric value for score threshold
#' @param human_total The total number of detections in the gold standard, typically from human listening data (e.g., the main report)
#'
#' @keywords internal
#'
#' @import dplyr
#'
#' @return A vector of precision, recall, F-score, and threshold

.wt_calculate_prf <- local({

  message_shown <- FALSE

  function(threshold, data, human_total){
    # Summarize
    data_thresholded <- dplyr::filter(data, confidence >= threshold) |>
      summarize(precision = sum(tp)/(sum(tp) + sum(fp)),
                recall = sum(tp)/human_total) |>
      mutate(fscore = (2*precision*recall)/(precision + recall),
             threshold = threshold)

    if(anyNA(data_thresholded$precision) && !message_shown){
      message('No classifier detections for some higher selected thresholds; results will contain NAs')
      message_shown <<- TRUE
    }

    return(data_thresholded)
  }
})

#' Internal function to delete media
#'
#' @description Internal function to delete media.
#'
#' @param dir Directory containing files
#'
#' @keywords internal
#'

.delete_wav_files <- function(dir) {
  wav_files <- list.files(path = dir, pattern = "\\.wav$", recursive = TRUE, full.names = TRUE)
  file.remove(wav_files)
}

#' Internal function to get Organizations
#'
#' @description Internal function to get Organizations
#'
#' @keywords internal

.get_org_id <- function(organization) {

  if (is.numeric(organization)) {
    return(organization)
  } else if (is.character(organization)) {
    orgs <- .wt_api_gr(path = "/bis/get-all-readable-organizations")
    og <- httr2::resp_body_json(orgs)

    # Create a lookup table
    og_table <- tibble(
      org_id = purrr::map_dbl(og, ~ ifelse(!is.null(.x$id), .x$id, NA)),
      org_code = purrr::map_chr(og, ~ ifelse(!is.null(.x$name), .x$name, NA))
    )

    # Retrieve and return the numeric org_id
    return(og_table |>
             filter(org_code == organization) |>
             pull(org_id))
  }
  stop("Organization must be either numeric or character")
}




