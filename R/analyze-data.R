#' Set of analysis functions
#'
#' @section Summarise camera data by location, time interval, and species.
#'
#' @description This function takes your independent detection data and summarises it by location, specified time interval, and species.
#'
#' @param detect_data Detection data generated from `wt_ind_det()`.
#' @param raw_data The raw camera tag data, which is used to infer the effort (i.e. date ranges of operation) for each camera. Optionally, can supply effort_data directly instead.
#' @param time_interval Character; Can be either "full", "month", "week", or "day" (default).
#' @param variable Character; Can be either "detections" (default), "presence", "counts", or "all" (if you want all three).
#' @param output_format Character; The format of the dataframe returned to you. Can be either "wide" (default) or "long".
#' @param species_col Defaults to `species_common_name`. The column referring to species. Use to switch between common and scientific names of species, if you have both.
#' @param effort_data Optionally supply your own effort data.
#' @param exclude_out_of_range Logical; Remove days from effort when camera field-of-view is obscured.
#' @param project_col Defaults to `project_id`. The column referring to project in your effort data.
#' @param station_col Defaults to `location`. The column referring to each individual camera station/location in your effort data.
#' @param date_time_col Defaults to `image_date_time`. The column referring to image date-time stamp.
#' @param start_col Defaults to `start_date`. The column indicating the start date of the camera location
#' @param end_col Defaults to `end_date`. The column indicating the end date of the camera location
#' @param detection_id_col Defaults to `detection`. The column indicating the detection id
#' @param start_col_det Defaults to `start_time`. The column indicating the start time of the independent detections
#'
#' @import dplyr
#' @importFrom tidyr pivot_longer pivot_wider unnest crossing replace_na drop_na
#' @importFrom rlang is_missing
#' @export
#'
#' @examples
#' \dontrun{
#' summary <- wt_summarise_cam(
#' x, y, time_interval = "day", variable = "detections", output_format = "wide"
#' )
#' }
#'
#' @return A dataframe summarising your camera data by location, time interval, and species.

wt_summarise_cam <- function(detect_data, raw_data, time_interval = "day",
                             variable = "detections", output_format = "wide",
                             species_col = species_common_name, effort_data = NULL,
                             exclude_out_of_range = FALSE,
                             project_col = project_id, station_col = location,
                             date_time_col = image_date_time,
                             start_col = start_date, end_col = end_date,
                             detection_id_col = detection,
                             start_col_det = start_time) {

  # Make sure one of raw_data or effort_data is supplied
  if (rlang::is_missing(raw_data) & is.null(effort_data)) {
    stop("Please supply a value for one of `raw_data` or `effort_data`.")
  }

  # Check that only one is supplied
  if (!rlang::is_missing(raw_data) & !is.null(effort_data)) {
    stop("Please only supply a value for one of `raw_data` or `effort_data`.")
  }

  if (variable == "all") {
    variable <- c("detections", "counts", "presence")
  }

  # Todo - check that supplied data contains all necessary columns

  # Check timeframe variable
  int <- c("day", "week", "month", "full")
  if (!time_interval %in% int) {
    stop("Please select a valid time interval: 'day', 'week', 'month', or 'full'.")
  }

  # Check output format
  formats <- c("wide", "long")
  if (!output_format %in% formats) {
    message("Please specify `wide` or `long` in the output_format argument.")
  }

  # Because station_col is also a function and arguments are lazily evaluated,
  # we need to deparse/substitute to a string
  #station_col <- deparse(substitute(station_col))

  # Parse the raw or effort data to get time ranges for each camera deployment.
  if (!rlang::is_missing(raw_data)) {

    if (exclude_out_of_range == FALSE) {
      x <- raw_data |>
        group_by({{ project_col }}, {{ station_col }}) |>
        summarise(start_date = as.Date(min({{ date_time_col }})),
                  end_date = as.Date(max({{ date_time_col }}))) |>
        ungroup()

      if (any(c(is.na(x$start_date), is.na(x$end_date)))) {
        message("Parsing of image date time produced NAs, these will be dropped")
        x <- drop_na(x)
      }

      # Expand the time ranges into individual days of operation (smallest unit)
      x <- x |>
        group_by({{ project_col }}, {{ station_col }}) |>
        mutate(day = list(seq.Date(start_date, end_date, by = "day"))) |>
        tidyr::unnest(day) |>
        mutate(year = as.integer(format(day, "%Y"))) |>
        select({{ project_col }}, {{ station_col }}, year, day) |>
        ungroup()

    } else {
      x <- raw_data |>
        group_by({{ project_col }}, {{ station_col }}) |>
        arrange({{ date_time_col }}) |>
        mutate(period = rep(seq_along(rle(image_fov)$lengths), rle(image_fov)$lengths)) |>
        filter(image_fov == "WITHIN") |>
        group_by({{ project_col }}, {{ station_col }}, period) |>
        summarise(
          start_date = as.Date(min({{ date_time_col }})),
          end_date = as.Date(max({{ date_time_col }}))
        ) |>
        ungroup()

      if (any(c(is.na(x$start_date), is.na(x$end_date)))) {
        message("Parsing of image date time produced NAs, these will be dropped")
        x <- drop_na(x)
      }

      # Expand the time ranges into individual days of operation (smallest unit)
      x <- x |>
        group_by({{ project_col }}, {{ station_col }}, period) |>
        mutate(day = list(seq.Date(start_date, end_date, by = "day"))) |>
        tidyr::unnest(day) |>
        mutate(year = as.integer(format(day, "%Y"))) |>
        select({{ project_col }}, {{ station_col }}, year, day)
    }

  }

  # Based on the desired timeframe, assess when each detection occurred
  if (time_interval == "day" | time_interval == "full") {
    y <- detect_data |>
      mutate(year = as.integer(format({{ start_col_det }}, "%Y")),
             day = as.Date({{ start_col_det }}))
    grouping_cols <- c("year", "day")
  } else if (time_interval == "week") {
    y <- detect_data |>
      mutate(year = as.integer(format({{ start_col_det }}, "%Y")),
             week = as.integer(format({{ start_col_det }}, "%V")))  # ISO week
    grouping_cols <- c("year", "week")
  } else if (time_interval == "month") {
    y <- detect_data |>
      mutate(year = as.integer(format({{ start_col_det }}, "%Y")),
             month = format({{ start_col_det }}, "%B"))  # Full month name
    grouping_cols <- c("year", "month")
  }

  # Summarise variable of interest
  y <- y |>
    group_by(across(all_of(grouping_cols)), {{ project_col }}, {{ station_col }}, {{ species_col }}) |>
    summarise(detections = n(),
              counts = sum(max_animals)) |>
    ungroup() |>
    mutate(presence = ifelse(detections > 0, 1, 0))

  # Species present in the data
  sp <- y |> select({{ species_col }}) |> distinct()

  # Create long df object of all species x location x timeframe combos
  if (time_interval == "day") {
    z <- x |>
      mutate(n_days_effort = 1) |>
      crossing(sp) |>
      left_join(y) |>
      mutate(across(6:8, ~ tidyr::replace_na(.x, 0)))
  } else if (time_interval == "week") {
    x <- x |>
      mutate(week = as.numeric(format(day, "%V"))) |>
      group_by({{ project_col }}, {{ station_col }}, year, week) |>
      tally(name = "n_days_effort") |>
      ungroup()
    z <- x |>
      crossing(sp) |>
      left_join(y) |>
      mutate(across(7:9, ~ tidyr::replace_na(.x, 0)))
  } else if (time_interval == "month") {
    x <- x |>
      mutate(month = format(day, "%B")) |>
      group_by({{ project_col }}, {{ station_col }}, year, month) |>
      tally(name = "n_days_effort") |>
      ungroup()
    z <- x |>
      crossing(sp) |>
      left_join(y) |>
      mutate(across(7:9, ~ tidyr::replace_na(.x, 0)))
  } else if (time_interval == "full") {
    z <- x |>
      crossing(sp) |>
      left_join(y) |>
      mutate(across(all_vars, ~ tidyr::replace_na(.x, 0))) |>
      group_by({{ project_col }}, {{ station_col }}, year, {{ species_col }}) |>
      summarise(detections = sum(detections),
                counts = sum(counts),
                presence = ifelse(any(presence == 1), 1, 0)) |>
      ungroup()
  }

  # Make wide if desired
  if (output_format == "wide") {
    z <- z |>
      tidyr::pivot_wider(id_cols = 1:5, names_from = {{ species_col }}, values_from = {{ variable }}, names_sep = ".")
  } else if (output_format == "long") {
    z <- z |> dplyr::select(1:6, {{ variable }}) |>
      tidyr::pivot_longer(cols = {{ variable }}, names_to = "variable", values_to = "value")
  }

  return(z)
}

#' Evaluate independent camera detections
#'
#' @description Create an independent detections dataframe using camera data from WildTrax
#'
#' @param x A dataframe of camera data; preferably, the main report from `wt_download_report()`.
#' @param threshold Numeric; time interval to parse out independent detections.
#' @param units The threshold unit. Can be one of three values, "seconds", "minutes", "hours".
#' @param datetime_col Defaults to `image_date_time`; The column indicating the timestamp of the image.
#' @param remove_human Logical; Should human and human-related tags (e.g. vehicles) be removed? Defaults to TRUE.
#' @param remove_domestic Logical; Should domestic animal tags (e.g. cows) be removed? Defaults to TRUE.
#'
#' @import dplyr
#' @importFrom rlang is_missing
#' @export
#'
#' @examples
#' \dontrun{
#' detections <- wt_ind_detect(x = df, threshold = 30, units = "minutes")
#' }
#'
#' @return A dataframe of independent detections in your camera data, based on the threshold you specified. The df will include information about the duration of each detection, the number of images, the average number of individual animals per image, and the max number of animals in the detection.

wt_ind_detect <- function(x, threshold, units = "minutes", datetime_col = image_date_time, remove_human = TRUE, remove_domestic = TRUE) {

  # Check that x is a dataframe
  if (!is.data.frame(x)) {
    stop("The first argument must supply a dataframe.")
  }

  # Ensure that datetime_col is of class POSIXct; if not, try to convert.
  name <- enquo(datetime_col) |> quo_name()
  if (!inherits(x[[name]], c("POSIXct"))) {
    x <- x |> mutate({{datetime_col}} := as.POSIXct({{datetime_col}}, format = "%Y-%m-%d %H:%M:%S", tz = "UTC"))
    message("Your datetime_col has been converted to a POSIXct DateTime.")
  }
  # Check if x contains the required columns - standard output from WildTrax. Probably should make this more flexible.
  req_cols <- c("project_id", "location", "species_common_name", "individual_count")
  if (!all(req_cols %in% colnames(x))) {
    stop("Important columns are missing from the data you have supplied. All of `project_id`, `location`, `species_common_name`, and `individual_count` are required.")
  }

  # Check that the units argument is either seconds, minutes, or hours
  if (!units %in% c("seconds", "minutes", "hours")) {
    stop("Please use 'seconds', 'minutes', or 'hours' as your threshold unit.")
  }

  # Convert threshold to seconds
  if (units == "minutes") {
    threshold <- threshold  * 60
  } else if (units == "hours") {
    threshold <- threshold * 60 * 60
  } else {
    threshold
  }

  # Tags to discard - not sure if UNKNOWN is ever wanted?
  t <- c("NONE", "STAFF/SETUP", "UNKNOWN")
  if (remove_human) {
    # Standard WildTrax tags that refer to human(ish) objects
    t <- c(t, "Human", "Vehicle", "Unknown Vehicle", "All Terrain Vehicle", "Train", "Heavy Equipment")
  }
  x <- filter(x, !species_common_name %in% t)
  if (remove_domestic) {
    # All tags in WildTrax that refer to domestic animals begin with 'Domestic __'
    x <- filter(x, !grepl("^Domestic", species_common_name))
  }

  # Create ordered dataframe, and calculate time interval between images.
  x1 <- x |>
    # Sometimes VNA sneaks in here
    mutate(individual_count = as.numeric(ifelse(individual_count == "VNA", 1, individual_count))) |>
    # Amalgamate tags of same species in same image; currently broken into two separate rows
    # Use image_id because sometimes {{datetime_col}} is same for 2 images
    group_by(location, image_id, species_common_name) |>
    mutate(individual_count = sum(individual_count)) |>
    distinct(location, {{datetime_col}}, species_common_name, individual_count, .keep_all = TRUE) |>
    ungroup() |>
    # Order the dataframe
    arrange(project_id, location, {{datetime_col}}, species_common_name) |>
    group_by(project_id, location, species_common_name) |>
    # Calculate the time difference between subsequent images
    mutate(interval = as.numeric(difftime({{datetime_col}}, lag({{datetime_col}}), units = "secs"))) |>
    # Is this considered a new detection?
    mutate(new_detection = ifelse(is.na(interval) | abs(interval) >= threshold, TRUE, FALSE)) |>
    ungroup() |>
    # Number independent detections
    mutate(detection = c(1, cumsum(new_detection[-1]) + 1))

  # Summarise detections
  x2 <- x1 |>
    group_by(detection, project_id, location, species_common_name) |>
    summarise(start_time = min({{datetime_col}}),
              end_time = max({{datetime_col}}),
              total_duration_seconds = as.numeric(difftime(end_time, start_time, units = "secs")),
              n_images = n(),
              avg_animals_per_image = mean(individual_count),
              max_animals = max(individual_count)) |>
    ungroup()

  # Return x2
  return(x2)

}
