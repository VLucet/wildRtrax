#' Scan acoustic data to a standard format
#'
#' @description Scans directories of audio data and returns the standard naming conventions
#'
#' @param path Character; The path to the directory with audio files you wish to scan. Can be done recursively.
#' @param file_type Character; Takes one of four values: wav, wac, flac or all. Use "all" if your directory contains many types of files.
#' @param extra_cols Boolean; Default set to FALSE for speed. If TRUE, returns additional columns for file duration, sample rate and number of channels.
#'
#' @import fs tibble dplyr tuneR purrr seewave
#' @importFrom rlang env_has current_env
#' @importFrom tidyr separate pivot_longer unnest_longer
#' @export
#'
#' @examples
#' \dontrun{
#' wt_audio_scanner(path = ".", file_type = "wav", extra_cols = T)
#' }
#'
#' @return A tibble with a summary of your audio files.

wt_audio_scanner <- function(path, file_type, extra_cols = F) {

  # Create regex for file_type
  if (file_type == "wav" || file_type == "WAV") {
    file_type_reg <- "\\.wav$|\\.WAV$"
  } else if (file_type == "wac") {
    file_type_reg <- "\\.wac$"
  } else if (file_type == "flac") {
    file_type_reg <- "\\.flac$"
  } else if (file_type == "all") {
    file_type_reg <- "\\.wav$|\\.wac$|\\.WAV$|\\.flac$"
  } else {
    # Throw error if the file_type is not set to wav, wac, flac, or all..
    stop (
      "For now, this function can only be used for wav, wac and/or flac files. Please specify either 'wac', 'wav', 'flac' or 'all' with the file_type argument."
    )
  }

  # Scan files, gather metadata
  df <- tibble::as_tibble(x = path) |>
    (function(df) {
      cat("Reading files from directory...\n")
      df
    })() |>
    dplyr::mutate(file_path = purrr::map(
      .x = value,
      .f = ~ fs::dir_ls(
        path = .x,
        regexp = file_type_reg,
        recurse = TRUE,
        fail = FALSE
      )
    ))
  # Check if nothing was returned
  if (nrow(df) == 0) {
    stop (
      "No files of the specified file type were found in this directory."
    )
  }

  # Create the main tibble
  df <- df |>
    tidyr::unnest_longer(file_path) |>
    dplyr::mutate(size_Mb = round(purrr::map_dbl(.x = file_path, .f = ~ fs::file_size(.x)) / 10e5, digits = 2), # Convert file sizes to megabytes
                  file_path = as.character(file_path)) |>
    dplyr::select(file_path, size_Mb) |>
    dplyr::filter(!size_Mb < 1) |> # zero-length file protection
    dplyr::mutate(file_name = sub("\\..*", "", basename(file_path)),
                  file_type = sub('.*\\.(\\w+)$', '\\1', basename(file_path))) |>
    # Parse location, recording date time and other temporal columns
    tidyr::separate(file_name, into = c("location", "recording_date_time"), sep = "(?:_0\\+1_|_|__0__|__1__)", extra = "merge", remove = FALSE) |>
    dplyr::mutate(recording_date_time = sub('.+?(?:__)', '', recording_date_time)) |>
    dplyr::mutate(recording_date_time = as.POSIXct(strptime(recording_date_time, format = "%Y%m%d_%H%M%S"))) |>
    dplyr::mutate(julian = as.POSIXlt(recording_date_time)$yday + 1,
           year = as.numeric(format(recording_date_time,"%Y")),
           gps_enabled = dplyr::case_when(grepl('\\$', file_name) ~ TRUE)) |>
    dplyr::arrange(location, recording_date_time) |>
    dplyr::group_by(location, year, julian) |>
    dplyr::mutate(time_index = dplyr::row_number()) |> # Create time index - this is an ordered list of the recording per day, e.g. first recording of the day = 1, second equals 2, etc.
    dplyr::ungroup()

  if (extra_cols == FALSE) {
    df_final_simple <- df # Omit the extra columns if chosen
  } else {

    # Scan the wav files first
    if ("wav" %in% df$file_type) {
      df_wav <- df %>%
        dplyr::filter(file_type == "wav") %>%
        dplyr::mutate(data = purrr::map(.x = file_path, .f = ~ tuneR::readWave(.x, from = 0, to = Inf, units = "seconds", header = TRUE))) %>%
        dplyr::mutate(length_seconds = purrr::map_dbl(.x = data, .f = ~ round(purrr::pluck(.x[["samples"]]) / purrr::pluck(.x[["sample.rate"]]), 2)),
                      sample_rate = purrr::map_dbl(.x = data, .f = ~ round(purrr::pluck(.x[["sample.rate"]]), 2)),
                      n_channels = purrr::map_dbl(.x = data, .f = ~ purrr::pluck(.x[["channels"]]))) %>%
        dplyr::select(-data)
    }

    #Then wac files
    if ("wac" %in% df$file_type) {
      df_wac <- df %>%
        dplyr::filter(file_type == "wac") %>%
        dplyr::mutate(wac_info = purrr::map(.x = file_path, .f = ~ wt_wac_info(.x)),
                      sample_rate = purrr::map_dbl(.x = wac_info, .f = ~ purrr::pluck(.x[["sample_rate"]])),
                      length_seconds = purrr::map_dbl(.x = wac_info, .f = ~ round(purrr::pluck(.x[["length_seconds"]]), 2)),
                      n_channels = purrr::map_dbl(.x = wac_info, .f = ~ purrr::pluck(.x[["n_channels"]]))) %>%
        dplyr::select(-wac_info)
    }

    #Finally flac
    if ("flac" %in% df$file_type) {
      df_flac <- df %>%
        dplyr::filter(file_type == "flac") %>%
        dplyr::mutate(flac_info = purrr::map(.x = file_path, .f = ~ wt_flac_info(.x)),
                      sample_rate = purrr::map_dbl(.x = flac_info, .f = ~ purrr::pluck(.x, 1)),
                      length_seconds = purrr::map_dbl(.x = flac_info, .f = ~ round(purrr::pluck(.x, 3), 2)),
                      n_channels = 0) %>%
        dplyr::select(-flac_info)
    }
  }

  # Stitch together
  if (rlang::env_has(rlang::current_env(), "df_final_simple")) {
    df_final <- df_final_simple
  } else if (exists("df_wav") & !exists("df_wac") & !exists("df_flac")) {
    df_final <- dplyr::bind_rows(df_wav)
  } else if (exists("df_wav") & exists("df_wac") & !exists("df_flac")) {
    df_final <- dplyr::bind_rows(df_wav, df_wac)
  } else if (exists("df_wav") & !exists("df_wac") & exists("df_flac")) {
    df_final <- dplyr::bind_rows(df_wav, df_flac)
  } else if (!exists("df_wav") & exists("df_wac") & !exists("df_flac")) {
    df_final <- dplyr::bind_rows(df_wac)
  } else if (!exists("df_wav") & !exists("df_wac") & exists("df_flac")) {
    df_final <- dplyr::bind_rows(df_flac)
  } else if (!exists("df_wav") & exists("df_wac") & exists("df_flac")) {
    df_final <- dplyr::bind_rows(df_wac, df_flac)
  } else if (exists("df_wav") & exists("df_wac") & exists("df_flac")) {
    df_final <- dplyr::bind_rows(df_wac, df_wav, df_flac)
  }

  # Return final data frame
  return(df_final)

}

#' Extract relevant metadata from a wac file
#'
#' @description Scrape relevant information from wac (Wildlife Acoustics) file
#'
#' @param path Character; The wac file path
#'
#' @export
#'
#' @return a list with relevant information

wt_wac_info <- function(path) {
  if (sub('.*\\.(\\w+)$', '\\1', basename(path)) != "wac") {
    stop("This is not a wac file.")
  }

  f <- file(path, open = "rb")
  on.exit(close(f))

  name <- readChar(f, 4)
  version <-
    readBin(
      con = f,
      what = integer(),
      size = 1,
      endian = "little"
    )
  n_channels <-
    readBin(
      con = f,
      what = integer(),
      size = 1,
      endian = "little"
    )
  frame_size <-
    readBin(
      con = f,
      what = integer(),
      size = 2,
      endian = "little"
    )
  block_size <-
    readBin(
      con = f,
      what = integer(),
      size = 2,
      endian = "little"
    )
  flags <-
    readBin(
      con = f,
      what = integer(),
      size = 2,
      endian = "little"
    )
  sample_rate <-
    readBin(
      con = f,
      what = integer(),
      size = 4,
      endian = "little"
    )
  samples <-
    readBin(
      con = f,
      what = integer(),
      size = 4,
      endian = "little"
    )

  if (n_channels == 1) {
    stereo <- FALSE
  } else {
    stereo <- TRUE
  }

  length_seconds = samples / sample_rate

  return(
    out = list(
      sample_rate = sample_rate,
      n_channels = n_channels,
      length_seconds = length_seconds
    )
  )

}

#' Extract relevant metadata from a flac file
#'
#' @description Scrape relevant information from flac file
#'
#' @param path Character; The flac file path
#'
#' @importFrom seewave wav2flac
#' @importFrom tuneR readWave
#' @export
#'
#' @return a list with relevant information

wt_flac_info <- function(path) {

  if (sub('.*\\.(\\w+)$', '\\1', basename(path)) != "flac") {
    stop("This is not a flac file.")
  }

  newfile <- gsub(".flac", ".wav", path)
  seewave::wav2flac(path, reverse = T)
  info <- tuneR::readWave(newfile, header = T)
  file.remove(newfile)

  return(
    out = list(
      sample_rate = info$sample.rate,
      n_channels = info$n_channels,
      length_seconds = info$samples / info$sample.rate
    )
  )

}

#' Get acoustic index values from audio
#'
#' @description For generating acoustic indices and false-colour spectrograms using QUT Ecoacoustics **A**nalysis **P**rograms software. See \url{https://github.com/QutEcoacoustics/audio-analysis} for information about usage and installation of the AP software.
#' Note that this function relies on having this software installed locally.
#'
#' This function will batch calculate summary and spectral acoustic indices and generate false-colour spectrograms for a folder of audio files using the Towsey.Acoustic configuration (yml) file from the AP software.
#' You can use the output from \code{`wt_audio_scanner()`} in the function, or define a local folder with audio files directly.
#'
#' @param x (optional) A data frame or tibble; must contain the absolute audio file path and file name. Use output from \code{`wt_audio_scanner()`}.
#' @param fp_col If x is supplied, the column containing the audio file paths. Defaults to file_path.
#' @param audio_dir (optional) Character; path to directory storing audio files.
#' @param output_dir Character; path to directory where you want outputs to be stored.
#' @param path_to_ap Character; file path to the AnalysisPrograms software package. Defaults to "C:\\AP\\AnalysisPrograms.exe".
#' @param delete_media Logical; when TRUE, removes the underlying sectioned wav files from the Towsey output. Leave to TRUE to save on space after runs.
#'
#' @import dplyr
#' @export
#'
#' @return Output will return to the specific root directory

wt_run_ap <- function(x = NULL, fp_col = file_path, audio_dir = NULL, output_dir, path_to_ap = "C:\\AP\\AnalysisPrograms.exe", delete_media = FALSE) {

  # Make sure at least (and only) one of x or audio_folder has been supplied
  if (is.null(x) & is.null(audio_dir)) {
    stop(
      "Please supply either a dataframe with the x argument, or a path to a directory of audio files with the audio_dir argument.",
      call. = TRUE
    )
  } else if (!is.null(x) & !is.null(audio_dir)) {
    stop("Please only supply one of x or audio_dir", call. = TRUE)
  }

  # Check if output_dir is supplied
  if (missing(output_dir)) {
    stop(
      "Please specify a path to a local directory where you would like outputs to be stored.",
      call. = TRUE
    )
  }

  # Supported AP audio formats
  supported_formats <-
    "\\.wav$|\\.mp3$|\\.ogg$|\\.flac$|\\.wv$|\\.webm$|\\.wma$"

  # Will support wac in 1.0.1
  convert <-
    "\\.wac$"

  # List audio files for analysis (vector)
  if (!is.null(x)) {
    # Ensure fp_col is a column name of x
    column <- dplyr::enquo(fp_col) %>%
      dplyr::quo_name()
    if (!column %in% names(x)) {
      stop("The value in fp_col does not refer to a column in x.")
    }
    files <- x %>%
      dplyr::filter(grepl(supported_formats, {{fp_col}})) %>%
      dplyr::select({{fp_col}}) %>%
      dplyr::pull()
  } else {
    files <- list.files(audio_dir, pattern = supported_formats, full.names = TRUE)
  }

    print("Starting AnalysisPrograms run - this may take a while depending on your machine and how many files you want to process...")

    files <- files %>%
      tibble::as_tibble() %>%
      dplyr::rename("file_path" = 1) %>%
      purrr::map(.x = .$file_path, .f = ~suppressMessages(system2(path_to_ap, sprintf('audio2csv "%s" "Towsey.Acoustic.yml" "%s" "-p"', .x, output_dir))))

    if (delete_media == TRUE) {
      .delete_wav_files(output_dir)
      message("Deleting media as requested. This may take a moment...")
    }

  return(message('Done AP Run! Check output folder for results and then run wt_glean_ap for visualizations.'))

}

#' Extract and plot relevant acoustic index metadata and LDFCs
#'
#' @description This function will use a list of media files from a `wt_*` work flow and outputs from `wt_run_ap()`
#' in order to generate summary plots of acoustic indices and long-duration false-colour spectrograms. This can
#' be viewed as the "final step" in interpreting acoustic index and LDFC values from your recordings.
#'
#' @param x A data frame or tibble; must contain the file name. Use output from \code{`wt_audio_scanner()`}.
#' @param input_dir Character; A folder path where outputs from \code{`wt_run_ap()`} are stored.
#' @param purpose Character; type of filtering you can choose from
#' @param include_ind Logical; Include index results
#' @param include_ldfcs Logical; Include LDFC results
#' @param borders Logical; Include borders to define different recordings
#'
#' @import dplyr ggplot2
#' @importFrom tidyr pivot_longer
#' @importFrom purrr reduce
#' @importFrom readr read_csv
#' @importFrom magick image_read image_append image_border
#' @export
#'
#' @examples
#' \dontrun{
#' wt_glean_ap(x = wt_audio_scanner_data, input_dir = "/path/to/my/files")
#' }
#'
#' @return Output will return the merged tibble with all information, the summary plots of the indices and the LDFC

wt_glean_ap <- function(x = NULL, input_dir, purpose = c("quality","abiotic","biotic"), include_ind = TRUE, include_ldfcs = TRUE, borders = F) {

  # Check to see if the input exists and reading it in
  files <- x

  #Purpose lists
  if (purpose == "quality") {
    purpose_list <- c("Snr","BackgroundNoise")
  } else if (purpose == "abiotic") {
    purpose_list <- c("ClippingIndex","TemporalEntropy","Ndsi")
  } else if (purpose == "biotic") {
    purpose_list <- c("HighFreqCover","MidFreqCover","LowFreqCover","AcousticComplexity","Ndsi")
  } else if (is.null(purpose)) {
    purpose_list <- list_all
  }


  # Check to see if the input exists and reading it in
  if (dir.exists(input_dir)) {
    ind <-
      fs::dir_ls(input_dir, regexp = "*.Indices.csv", recurse = T) |>
      purrr::map_dfr( ~ readr::read_csv(.x, show_col_types = F)) |>
      dplyr::relocate(c(FileName, ResultMinute)) |>
      dplyr::select(-c(ResultStartSeconds, SegmentDurationSeconds,RankOrder,ZeroSignal)) |>
      tidyr::pivot_longer(!c(FileName, ResultMinute),
                   names_to = "index_variable",
                   values_to = "index_value")

    ldfcs <-
      fs::dir_info(input_dir, regexp = "*__2Maps.png", recurse = T) |>
      dplyr::select(path) |>
      dplyr::rename("image" = 1) |>
      dplyr::mutate(file_name = sub('__2Maps.png$', '', basename(image)))

  } else {
    stop("Cannot find this directory")
  }

  # Join the indices and LDFCs to the media
  data_to_join <- list(
    files,
    if (include_ind) ind else NULL,
    if (include_ldfcs) ldfcs else NULL
  ) %>%
    discard(is.null)

  data_to_join <- purrr::map(data_to_join, function(df) {
    if ("file_name" %in% names(df)) {
      df <- dplyr::rename(df, FileName = file_name)
    }
    df
  })

  joined <- purrr::reduce(data_to_join, ~ dplyr::inner_join(.x, .y, by = "FileName"))

  if(nrow(joined) > 0){
    print('Files joined!')
  }

  joined_purpose <- joined |>
    dplyr::filter(index_variable %in% purpose_list)

  # Plot a summary of the indices
  plotted <- joined_purpose %>%
    ggplot2::ggplot(., aes(x=julian, y=index_value, group=julian, fill=index_variable)) +
    ggplot2::geom_boxplot() +
    ggplot2::scale_fill_viridis_d() +
    ggplot2::theme_bw() +
    ggplot2::facet_wrap(~index_variable, scales = "free_y") +
    ggplot2::theme(legend.position="right", legend.box = "horizontal") +
    ggplot2::guides(fill = guide_legend(title="New Legend Title")) +
    ggplot2::guides(fill = guide_legend(nrow = 25, ncol = 1)) +
    ggplot2::xlab("Julian Date") +
    ggplot2::ylab("Index value") +
    ggplot2::ggtitle("Summary of indices")

  # Plot the LDFC
  ldfc <- joined_purpose |>
    dplyr::select(image) |>
    dplyr::distinct() |>
    purrr::map(function(x) {
      # Define your condition

      # Apply border only if the condition is TRUE
      img <- magick::image_read(x)
      if (borders == TRUE) {
        img <- magick::image_border(img, color = "#00008B", geometry = "0.75x0.75")
      }
      return(img)
    }) %>%
    do.call("c", .) %>%
    magick::image_append()

  # Trim top and bottom and crop
  img_info <- magick::image_info(ldfc)
  img_width <- img_info$width
  img_height <- img_info$height

  top_crop_height <- as.integer(img_height * 0.061)
  bottom_crop_height <- as.integer(img_height * 0.028)
  remaining_height <- as.integer(img_height - top_crop_height - bottom_crop_height)

  cropped_img <- ldfc %>%
    magick::image_crop(geometry = sprintf("%dx%d+0+%d",
                                  img_width,
                                  remaining_height,
                                  top_crop_height))

  return(list(joined,plotted,cropped_img))

}

#' Get signals from specific windows of audio
#'
#' @description Signal level uses amplitude and frequency thresholds in order to detect a signal.
#'
#' @param path The path to the wav file
#' @param fmin The frequency minimum
#' @param fmax The frequency maximum
#' @param threshold The desired threshold
#' @param channel Choose "left" or "right" channel
#' @param aggregate Aggregate detections by this number of seconds, if desired
#'
#' @import dplyr
#' @importFrom tuneR readWave
#' @importFrom seewave spectro
#' @export
#'
#' @examples
#' \dontrun{
#' df <- wt_signal_level(path = "")
#' }
#'
#' @return A list object containing the following four elements: output (dataframe), aggregated (boolean), channel (character), and threshold (numeric)
#'

wt_signal_level <- function(path, fmin = 500, fmax = NA, threshold, channel = "left", aggregate = NULL) {

  # Load wav object from path
  wav_object <- tuneR::readWave(path)

  # Sampling frequency
  sampling_frequency <- wav_object@samp.rate

  # Recording duration
  recording_duration <- length(wav_object@left) / sampling_frequency

  # Check that channel is set to either left or right
  if (!(channel == "left" | channel == "right")) {
    stop('Please specify "left" or "right" channel.')
  }

  if (channel == "left") {
    wav_object <- wav_object@left
  } else {
    if (length(wav_object@right) %in% c(0, 1)) {
      stop('Channel set to "right", but no right channel')
    }
    wav_object <- wav_object@right
  }

  # Remove DC offset
  wav_object <- wav_object - mean(wav_object)

  # Set breaks
  breaks <- seq(0, recording_duration, 300)
  if (breaks[length(breaks)] != recording_duration) {
    breaks[length(breaks) + 1] <- recording_duration
  }

  samps <- breaks * sampling_frequency
  samps[1] <- 1

  times = c()
  rsl.out <- c()

  for (i in 2:length(breaks)) {
    print(paste0('Calculating segment ', i - 1, ' out of ', length(breaks) - 1))
    s <- seewave::spectro(
      wav_object[samps[i - 1]:samps[i]],
      f = sampling_frequency,
      wn = "hamming",
      wl = 512,
      ovlp = 50,
      plot = FALSE,
      norm = FALSE
    )
    # Filter spectrogram
    subset <- which(s$freq >= fmin / 1000)
    if (!is.na(fmax)) {
      subset <- which(s$freq >= fmin / 1000 & s$freq <= fmax / 1000)
    }
    s$freq <- s$freq[subset]
    s$amp <- s$amp[subset,]
    # Calculate max RSL for each window
    rsl <- apply(s$amp, 2, max)
    # Edit times for the chunk
    s$time <- s$time + breaks[i - 1]
    times <- c(times, s$time[rsl > threshold])
    rsl.out <- c(rsl.out, rsl[rsl > threshold])
  }

  if (length(times) > 0) {
    sl <- data.frame(time = times, rsl = rsl.out)
  } else {
    sl <- NA
  }

  # Aggregate (if desired)
  if (!is.null(aggregate)) {
    if (!is.na(sl)) {
      sl <- sl %>%
        dplyr::mutate(
          time_lag = dplyr::lag(time),
          new_detection = ifelse((time - time_lag) >= aggregate, 1, 0),
          detection = c(0, cumsum(new_detection[-1])) + 1
        ) %>%
        dplyr::group_by(detection) %>%
        dplyr::summarise(
          mean_rsl = mean(rsl),
          start_time_s = min(time),
          end_time_s = max(time)
        ) %>%
        dplyr::ungroup() %>%
        dplyr::mutate(detection_length = end_time_s - start_time_s)
      aggregated <- TRUE
    } else {
      sl
      aggregated <- FALSE
      warning("No signals met the threshold criteria. Output not aggregated.")
    }
  } else {
    if (!is.na(sl)) {
      sl
      aggregated <- FALSE
    } else {
      sl
      aggregated <- FALSE
      warning("No signals met the threshold critera.")
    }
  }

  # Create list object
  d <- list(
    output = sl,
    aggregated = aggregated,
    channel = channel,
    threshold = threshold
  )

  return(d)

}

#' Segment large audio files
#'
#' @description "Chops" up wav files into many smaller files of a desired duration and writes them to an output folder.
#'
#' @param input A data frame or tibble containing information about audio files
#' @param segment_length Numeric; Segment length in seconds. Modulo recording will be exported should there be any trailing time left depending on the segment length used
#' @param output_folder Character; output path to where the segments will be stored
#'
#' @import tuneR dplyr
#' @export
#'
#' @examples
#' \dontrun{
#' wt_chop(input = my_files, segment_length = 60, output_folder = "output_folder")
#' }
#'
#' @return No return value, called for file-writing side effects.

wt_chop <- function(input = NULL, segment_length = NULL, output_folder = NULL) {
  # Check if output folder exists
  if (!dir.exists(output_folder)) {
    stop("The output directory does not exist.")
  }

  # Validate segment length
  if (is.null(segment_length) || !is.numeric(segment_length) || segment_length <= 0) {
    stop("Segment length must be a positive numeric value.")
  }

  # Check for input and output folder overlap
  if (any(grepl(normalizePath(output_folder), normalizePath(input$file_path)))) {
    stop("The output folder cannot be the same as the input file directory to prevent overwriting.")
  }

  # Prepare input data
  inp <- input |>
    dplyr::select(file_path, recording_date_time, location, file_type, length_seconds) |>
    tibble::add_column(length_sec = segment_length) |>
    dplyr::mutate(
      longer = ifelse(length_seconds >= length_sec, TRUE, FALSE),
      length_seconds = round(length_seconds, 0)
    )

  # Check for too short recordings
  if (any(inp$length_seconds < segment_length)) {
    stop("Some recordings are shorter than the segment length.")
  }

  # Generate start times and new file paths
  inp2 <- inp %>%
    dplyr::mutate(
      start_times = purrr::map2(length_seconds, length_sec, ~ seq(0, .x - .y, by = .y))
    ) %>%
    tidyr::unnest(start_times) %>%
    dplyr::filter(start_times + length_sec <= length_seconds) %>%
    dplyr::mutate(
      new_file = paste0(
        output_folder, "/", location, "_",
        format(recording_date_time + as.difftime(start_times, units = "secs"), "%Y%m%d_%H%M%S"), ".", file_type
      )
    ) %>%
    dplyr::mutate(across(c(length_sec, start_times), as.numeric))

  # Process audio files with validation
  inp2 %>%
    purrr::pmap(.l = list(file_path = .$file_path, new_file = .$new_file,
                          length_sec = .$length_sec, start_times = .$start_times),
                .f = ~ {
                  file_path <- ..1
                  new_file <- ..2
                  length_sec <- as.numeric(..3)
                  start_times <- as.numeric(..4)

                  cat("Processing:\n  File:", file_path, "\n  Start:", start_times,
                      "\n  Length:", length_sec, "\n  New File:", new_file, "\n")

                  if (!file.exists(file_path)) {
                    message("File not found: ", file_path)
                    return(NULL)
                  }

                  tryCatch({
                    tuneR::writeWave(
                      tuneR::readWave(file_path, from = start_times, to = start_times + length_sec, units = "seconds"),
                      filename = new_file,
                      extensible = TRUE
                    )
                  }, error = function(e) {
                    message("Error processing file: ", file_path, " - ", e$message)
                  })
                }
    )
}


#' Linking media to WildTrax
#'
#' Prepare media and data for upload to WildTrax
#'
#' The following suite of functions will help you wrangle media and data together
#' in order to upload them to WildTrax. You can make tasks(https://www.wildtrax.ca/home/resources/guide/projects/aru-projects.html)
#' and tags(https://www.wildtrax.ca/home/resources/guide/acoustic-data/acoustic-tagging-methods.html) using the results from a
#' `wt_audio_scanner()` tibble or the hits from one of two Wildlife Acoustics programs Songscope() and Kaleidoscpe().
#'
#' Creating tasks from media
#'
#' @section `wt_make_aru_tasks`
#'
#' @description `wt_make_aru_tasks()` uses a `wt_audio_scanner()` input tibble to create a task template to upload to a WildTrax project.
#'
#' @param input Character; An input `wt_audio_scanner()` tibble. If not a `wt_audio_scanner()` tibble, the data must contain at minimum the location, recording_date_time and file_path as columns.
#' @param output Character; Path where the output task csv file will be stored
#' @param task_method Character; Method type of the task. Options are 1SPM, 1SPT and None. See Methods(https://www.wildtrax.ca/home/resources/guide/acoustic-data/acoustic-tagging-methods.html) in WildTrax for more details.
#' @param task_length Numeric; Task length in seconds. Must be between 1 - 1800 and can be up to two decimal places.
#'
#' @import dplyr tibble
#' @export
#'
#' @examples
#' \dontrun{
#' wt_make_tasks(input = my_audio_tibble, output = tasks.csv, task_method = "1SPT", task_length = 180)
#' }
#'
#' @return A csv formatted as a WildTrax task template
#'
#' It's important that if the media hasn't been uploaded to WildTrax, that you do that first before trying to generate tasks in a project.
#' In parallel, you can select the files you want and upload and generate tasks in a project.

wt_make_aru_tasks <- function(input, output=NULL, task_method = c("1SPM","1SPT","None"), task_length) {

  task_prep <- input

  req_cols <- c("file_path","location","recording_date_time")

  if (!any(names(task_prep) %in% req_cols)){
    stop("Missing certain columns")
  }

  req_methods <- c("1SPM","1SPT","None")

  if (!(task_method %in% req_methods)) {
    stop("This isn't an accepted method. Use 1SPM, 1SPT or None.")
  }

  if ((is.numeric(task_length) & task_length >= 1 & task_length < 1800)==FALSE) {
    stop("task_length must be a number and between 1 and 1800 seconds.")
  }

  tasks <- task_prep |>
    dplyr::select(location, recording_date_time, length_seconds) |>
    dplyr::distinct() |>
    dplyr::mutate(taskLength = case_when(length_seconds < task_length ~ NA_real_, TRUE ~ task_length)) |> #Make sure recording length is long enough
    dplyr::select(-length_seconds) |>
    #Add the necessary task columns
    tibble::add_column(method = task_method, .after = "recording_date_time") |>
    tibble::add_column(status = "New", .after = "taskLength") |>
    tibble::add_column(transcriber = "", .after = "status") |>
    tibble::add_column(rain = "", .after = "transcriber") |>
    tibble::add_column(wind = "", .after = "rain") |>
    tibble::add_column(industryNoise = "", .after = "wind") |>
    tibble::add_column(otherNoise = "", .after = "industryNoise") |>
    tibble::add_column(audioQuality = "", .after = "otherNoise") |>
    tibble::add_column(taskComments = "", .after = "audioQuality") |>
    tibble::add_column(internal_task_id = "", .after = "taskComments")

  no_length <- tasks |>
    dplyr::filter(is.na(taskLength))

  if ((nrow(no_length)) > 0) {
    message(nrow(no_length), ' rows are shorter than the desired task length')
  }

  if (!is.null(tasks)) {
    message("Converted list of recordings to WildTrax tasks. Go to your WildTrax organization > Recordings Tab > Manage > Upload Recordings.
        Then go to your WildTrax project > Manage > Upload Tasks to upload the csv of tasks.")
  }

  if (is.null(output)) {
    return(tasks)
  } else {
    return(write.csv(tasks, output, row.names = F))
  }
}

#' Convert Kaleidoscope output to tags
#'
#'
#' @description `wt_kaleidoscope_tags` Takes the classifier output from Wildlife Acoustics Kaleidoscope and converts them into a WildTrax tag template for upload
#'
#' @param input Character; The path to the input csv
#' @param output Character; Path where the output file will be stored
#' @param freq_bump Boolean; Set to TRUE to add a buffer to the frequency values exported from Kaleidoscope. Helpful for getting more context around a signal in species verification
#'
#' @import dplyr tibble
#' @importFrom readr read_csv
#' @importFrom tidyr drop_na separate
#' @export
#'
#' @examples
#' \dontrun{
#' wt_kaleidoscope_tags(input = input.csv, output = tags.csv, freq_bump = T)
#' }
#'
#' @return A csv formatted as a WildTrax tag template

wt_kaleidoscope_tags <- function (input, output, freq_bump = T) {

  #Check to see if the input exists and reading it in
  if (file.exists(input)) {
    in_tbl <- readr::read_csv(input, col_names = TRUE, na = c("", "NA"), col_types = cols())
  } else {
    stop ("File cannot be found")
  }

  #Cleaning things up for the tag template
  in_tbl_wtd <- in_tbl |>
    dplyr::select(INDIR, `IN FILE`, DURATION, OFFSET, Dur, DATE, TIME, `AUTO ID*`, Fmin, Fmax) |>
    tidyr::separate(`IN FILE`, into = c("location", "recordingDate"), sep = "(?:_0\\+1_|_|__0__|__1__)", extra = "merge", remove = F) |>
    dplyr::select(-(DATE:TIME)) |>
    dplyr::relocate(location) |>
    dplyr::relocate(recordingDate, .after = location) |>
    dplyr::mutate(recordingDate = sub('.+?(?:__)', '', recordingDate))
    # Create date/time fields
    dplyr::mutate(recording_date_time = as.POSIXct(strptime(recording_date_time, format = "%Y-%m-%d %H:%M:%S"))) |> #Apply a time zone if necessary
    dplyr::rename("taskLength" = 5,
                  "startTime" = 6,
                  "tagLength" = 7,
                  "species" = 8,
                  "minFreq" = 9,
                  "maxFreq" = 10) |>
    dplyr::select(-(INDIR:`IN FILE`)) |>
    # Updating names to WildTrax species codes
    dplyr::mutate(species = case_when(species == "NoID" ~ "UBAT",
                                      species == "H_freq_Bat" ~ "HighF",
                                      species == "L_freq_Bat" ~ "LowF",
                                      TRUE ~ species),
                  startTime = dplyr::case_when(startTime == 0 ~ 0.1, TRUE ~ startTime)) |> #Adjusting startTime parameter
    tibble::add_column(method = "1SPT", .after = "recordingDate") |>
    tibble::add_column(transcriber = "Not Assigned", .after = "taskLength") |>
    dplyr::group_by(location, recordingDate, taskLength, species) |>
    dplyr::mutate(speciesIndividualNumber = row_number()) |>
    dplyr::ungroup() |>
    tibble::add_column(vocalization = "", .after = "speciesIndividualNumber") |>
    tibble::add_column(abundance = 1, .after= "vocalization") |>
    dplyr::mutate(vocalization = case_when(species == "Noise" ~ "Non-vocal", TRUE ~ "Call")) |>
    tibble::add_column(internal_tag_id = "", .after = "maxFreq") |>
    dplyr::mutate(recordingDate = as.character(recordingDate)) |>
    dplyr::rowwise() |>
    dplyr::mutate(tagLength = dplyr::case_when(tagLength > taskLength ~ taskLength, TRUE ~ tagLength)) |>
    dplyr::mutate(tagLength = dplyr::case_when(is.na(tagLength) ~ taskLength - startTime, TRUE ~ tagLength),
                  minFreq = dplyr::case_when(is.na(minFreq) ~ 12000, TRUE ~ minFreq * 1000),
                  maxFreq = dplyr::case_when(is.na(maxFreq) ~ 96000, TRUE ~ maxFreq * 1000)) |>
    dplyr::ungroup() |>
    dplyr::mutate_at(vars(taskLength,minFreq,maxFreq), ~round(.,2)) |>
    #Apply the frequency bump (+/- 10000 Hz)
    dplyr::mutate(minFreq = dplyr::case_when(freq_bump == TRUE ~ minFreq - 10000, TRUE ~ minFreq),
                  maxFreq = dplyr::case_when(freq_bump == TRUE ~ maxFreq + 10000, TRUE ~ maxFreq)) |>
    dplyr::relocate(taskLength, .after = method) |>
    dplyr::relocate(startTime, .after = abundance) |>
    dplyr::relocate(tagLength, .after = startTime) |>
    dplyr::relocate(minFreq, .after = tagLength) |>
    dplyr::relocate(maxFreq, .after = minFreq) |>
    dplyr::relocate(internal_tag_id, .after = maxFreq) |>
    tidyr::drop_na()

  #Write the file
  return(write.csv(in_tbl_wtd, file = output, row.names = F))

  print("Converted to WildTrax tags. Go to your WildTrax project > Manage > Upload Tags.")

}

#' Convert Songscope output to tags
#'
#' @param input Character; The path to the input csv
#' @param output Character; Path where the output file will be stored
#' @param my_output_file Character; Path of the output file
#' @param species_code Character; Short-hand code for the species (see wt_get_species)
#' @param vocalization_type Character; The vocalization type from either Song, Call, Non-Vocal, Night flight and Feeding Buzz
#' @param method Character; Include options from 1SPT, 1SPM or None
#' @param score_filter Numeric; Filter the detections by score
#' @param task_length Numeric; length of the task in seconds
#'
#' @import dplyr tibble
#' @importFrom readr read_table
#' @importFrom tidyr separate
#' @export
#'
#' @return A csv formatted as a WildTrax tag template

wt_songscope_tags <- function (input, output = c("env","csv"),
                               my_output_file=NULL, species_code, vocalization_type,
                               score_filter, method = c("USPM","1SPT"), task_length) {

  #Check to see if the input exists and reading it in
  if (file.exists(input)) {
    in_tbl <- readr::read_table(input, col_names = F)
  } else {
    stop ("File cannot be found")
  }

  if ((output == "csv") & is.null(my_output_file)) {
    stop("Specify an output file name for the tag csv")
  } else if (output == "env") {
    print("Reading file...")
  }

  #Cleaning things up for the tag template
  in_tbl_wtd <- in_tbl %>%
    dplyr::rename("file_path" = 1) %>%
    dplyr::rename("startTime" = 2) %>%
    dplyr::rename("tagLength" = 3) %>%
    dplyr::rename("level" = 4) %>%
    dplyr::rename("Quality" = 5) %>%
    dplyr::rename("Score" = 6) %>%
    dplyr::rename("recognizer" = 7) %>%
    dplyr::rename("comments"= 8) %>%
    dplyr::mutate(file_name = strsplit(basename(file_path), "\\.")[[1]]) %>%
    tidyr::separate(file_name, into = c("location", "recordingDate"),
                    sep = "(?:_0\\+1_|_|__0__|__1__)", extra = "merge", remove = F) %>%
    dplyr::mutate(startTime = as.numeric(startTime)) %>%
    dplyr::mutate(recordingDate = sub('.+?(?:__)', '', recordingDate)) |>
    dplyr::mutate(recording_date_time = as.POSIXct(strptime(recording_date_time, format = "%Y-%m-%d %H:%M:%S")))

  if (method == "USPM") {
    in_tbl_wtd <- in_tbl_wtd %>%
      tibble::add_column(method = "USPM", .after = "recordingDate") %>%
      tibble::add_column(taskLength = task_length, .after = "method") %>%
      tibble::add_column(transcriber = "Not Assigned", .after = "taskLength") %>%
      tibble::add_column(species = species_code, .after = "transcriber") %>%
      dplyr::group_by(location, recordingDate, taskLength, species) %>%
      dplyr::mutate(speciesIndividualNumber = row_number()) %>%
      dplyr::ungroup() %>%
      dplyr::mutate(vocalization = vocalization_type) %>%
      tibble::add_column(abundance = 1, .after= "vocalization") %>%
      dplyr::relocate(startTime, .after = abundance) %>%
      dplyr::relocate(tagLength, .after = startTime) %>%
      tibble::add_column(minFreq = "", .after= "tagLength") %>%
      tibble::add_column(maxFreq = "", .after= "minFreq") %>%
      tibble::add_column(internal_tag_id = "", .after = "maxFreq") %>%
      dplyr::select(location, recordingDate, method, taskLength, transcriber, species,
             speciesIndividualNumber, vocalization, abundance, startTime, tagLength,
             minFreq, maxFreq, internal_tag_id, Quality, Score) %>%
      dplyr::filter(Score >= score_filter)
  } else if (method == "1SPT") {
    in_tbl_wtd <- in_tbl_wtd %>%
      tibble::add_column(method = "1SPT", .after = "recordingDate") %>%
      tibble::add_column(taskLength = task_length, .after = "method") %>%
      tibble::add_column(transcriber = "Not Assigned", .after = "taskLength") %>%
      tibble::add_column(species = species_code, .after = "transcriber") %>%
      dplyr::group_by(location, recordingDate, taskLength, species) %>%
      dplyr::mutate(speciesIndividualNumber = row_number()) %>%
      dplyr::ungroup() %>%
      dplyr::filter(!speciesIndividualNumber > 1) %>%
      dplyr::mutate(vocalization = vocalization_type) %>%
      tibble::add_column(abundance = 1, .after= "vocalization") %>%
      dplyr::relocate(startTime, .after = abundance) %>%
      dplyr::relocate(tagLength, .after = startTime) %>%
      tibble::add_column(minFreq = "", .after= "tagLength") %>%
      tibble::add_column(maxFreq = "", .after= "minFreq") %>%
      tibble::add_column(internal_tag_id = "", .after = "maxFreq") %>%
      dplyr::select(location, recordingDate, method, taskLength, transcriber, species,
             speciesIndividualNumber, vocalization, abundance, startTime, tagLength,
             minFreq, maxFreq, internal_tag_id, Quality, Score) %>%
      dplyr::filter(Score >= score_filter)
  } else {
    stop("Only USPM and 1SPT uploads are supported at this time")
  }

  if (max(in_tbl_wtd$startTime > task_length)) {
    print("A heads up there are tags outside the length of the chosen task...")
  }

  #Write the file
  if (output == "env") {
    return(in_tbl_wtd)
    print("Converted to WildTrax tags. Review the output then go to your WildTrax project > Manage > Upload Tags.")
  } else if (output == "csv") {
    return(list(in_tbl_wtd, write.csv(in_tbl_wtd, file = my_output_file, row.names = F)))
    print("Converted to WildTrax tags. Go to your WildTrax project > Manage > Upload Tags.")
  }

}
